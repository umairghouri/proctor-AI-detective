using System;
using System.Threading;

namespace PDetector.Scanners
{
    /// <summary>
    /// Runs a UI Automation call on a dedicated STA thread behind a HARD wall-clock timeout,
    /// with a circuit breaker that gives up on UIA entirely once it has hung too often.
    ///
    /// WHY THIS EXISTS
    /// ---------------
    /// UI Automation is a cross-process COM protocol. Every property read is a blocking RPC into
    /// the browser. When the browser is busy - a heavy page, an open modal, a hung renderer, a tab
    /// mid-drag - the call does not fail, it BLOCKS, sometimes for tens of seconds. Called from the
    /// WinForms UI thread that is "(Not Responding)" painted over the detector window; called from
    /// a worker thread with no timeout that is a scan that never finishes.
    ///
    /// WHY WE ABANDON THE THREAD INSTEAD OF KILLING IT
    /// -----------------------------------------------
    /// net48 DOES have <c>Thread.Abort</c>, unlike .NET 5+. We deliberately DO NOT CALL IT.
    /// Aborting a thread that is blocked inside a COM cross-apartment call injects an exception at
    /// an arbitrary instruction inside the RPC channel: the STA's message pump, the proxy/stub
    /// marshalling state and the UIA client's internal caches are all left half-updated, and the
    /// usual consequence is that every later UIA call in the process fails or deadlocks. Killing
    /// one hung probe would poison all the rest. So the only correct design is:
    ///
    ///   * run the work on a throwaway background STA thread,
    ///   * stop waiting once the timeout expires and report "unknown", never "clean",
    ///   * let the thread leak - it is <c>IsBackground</c>, so it cannot keep the process alive
    ///     and the CLR will not wait for it at shutdown,
    ///   * and open a CIRCUIT BREAKER so a browser that hangs once does not cost us one leaked
    ///     thread per window for the rest of the scan.
    ///
    /// The circuit is deliberately tripped by CONSECUTIVE timeouts. One slow window on an
    /// otherwise healthy desktop should not disable tab reading; a browser that is wedged will
    /// time out every single time, and after <see cref="MaxConsecutiveTimeouts"/> of those we stop
    /// asking and let the caller record the blind spot as a Limitation.
    /// </summary>
    public sealed class StaTimeoutRunner
    {
        private readonly int _maxConsecutiveTimeouts;
        private readonly int _maxAbandonedThreads;
        private readonly TimeSpan _cooldown;

        /// <summary>Threads started but not yet finished. A hung thread never decrements this.</summary>
        private int _outstanding;

        /// <summary>Timeouts since the last success. Reset to 0 by any completed probe.</summary>
        private int _consecutiveTimeouts;

        /// <summary>Total timeouts over the runner's life, for the diagnostics text.</summary>
        private int _totalTimeouts;

        private long _cooldownUntilTicks;

        /// <summary>Set the first time the circuit opens, so the caller can quote a reason.</summary>
        private string? _circuitReason;

        private readonly object _reasonLock = new object();

        /// <param name="maxConsecutiveTimeouts">
        /// How many probes in a row may time out before UIA is abandoned for the rest of the scan.
        /// Two is deliberate: one timeout is a busy window, two in a row is a wedged browser.
        /// </param>
        /// <param name="maxAbandonedThreads">
        /// Hard ceiling on simultaneously-hung STA threads. Reached independently of the
        /// consecutive counter, because leaked threads cost address space whether or not the
        /// timeouts happened to be interleaved with successes.
        /// </param>
        /// <param name="cooldown">
        /// How long a timeout keeps the circuit open even if the consecutive count has not been
        /// reached. Scans are short, so this is effectively "the rest of this scan".
        /// </param>
        public StaTimeoutRunner(
            int maxConsecutiveTimeouts = 2,
            int maxAbandonedThreads = 3,
            TimeSpan? cooldown = null)
        {
            _maxConsecutiveTimeouts = Math.Max(1, maxConsecutiveTimeouts);
            _maxAbandonedThreads = Math.Max(1, maxAbandonedThreads);
            _cooldown = cooldown ?? TimeSpan.FromSeconds(20);
        }

        public int MaxConsecutiveTimeouts
        {
            get { return _maxConsecutiveTimeouts; }
        }

        /// <summary>Probes abandoned mid-flight over this runner's lifetime.</summary>
        public int TimeoutCount
        {
            get { return Volatile.Read(ref _totalTimeouts); }
        }

        /// <summary>STA threads started that have not come back. These are leaked, by design.</summary>
        public int OutstandingThreadCount
        {
            get { return Volatile.Read(ref _outstanding); }
        }

        /// <summary>
        /// True while we refuse to start new probes. Three independent triggers, any of which is
        /// enough: too many timeouts in a row, too many threads currently hung, or we are inside
        /// the cooldown window that the last timeout opened.
        /// </summary>
        public bool CircuitOpen
        {
            get
            {
                if (Volatile.Read(ref _consecutiveTimeouts) >= _maxConsecutiveTimeouts) return true;
                if (Volatile.Read(ref _outstanding) >= _maxAbandonedThreads) return true;
                return DateTime.UtcNow.Ticks < Interlocked.Read(ref _cooldownUntilTicks);
            }
        }

        /// <summary>
        /// Human-readable reason the circuit opened, suitable for ScanReport.Limitations, or null
        /// while it has never opened. Stated as a blind spot, never as a clean result.
        /// </summary>
        public string? CircuitReason
        {
            get { lock (_reasonLock) { return _circuitReason; } }
        }

        /// <summary>
        /// Run <paramref name="work"/> on a fresh background STA thread.
        /// Returns true only when the delegate ran to completion inside <paramref name="timeout"/>.
        /// Returns false - with <paramref name="result"/> left at default - when the circuit is
        /// open, when the thread could not be started, when the delegate threw, or when the
        /// timeout expired. Never throws.
        /// </summary>
        public bool TryRun<T>(Func<T> work, TimeSpan timeout, out T result, out Exception? error)
        {
            result = default!;
            error = null;

            if (work == null)
            {
                error = new ArgumentNullException("work");
                return false;
            }

            if (CircuitOpen)
            {
                error = new TimeoutException(CircuitReason ?? "UIA circuit breaker is open.");
                return false;
            }

            if (timeout <= TimeSpan.Zero)
            {
                error = new TimeoutException("No time budget left for a UIA probe.");
                return false;
            }

            T captured = default!;
            Exception? capturedError = null;

            // NOT a `using`: an abandoned worker can Set() this long after we have returned, so
            // ownership of the handle is shared. Whichever side arrives second disposes it.
            ManualResetEventSlim done = new ManualResetEventSlim(false);
            int disposeOwner = 0;

            Interlocked.Increment(ref _outstanding);

            Thread thread = new Thread(delegate ()
            {
                try
                {
                    captured = work();
                }
                catch (Exception ex)
                {
                    capturedError = ex;
                }
                finally
                {
                    // Only a thread that actually came back releases its slot. A thread wedged
                    // inside COM forever never reaches here - which is exactly what we want the
                    // outstanding-thread ceiling to count.
                    Interlocked.Decrement(ref _outstanding);
                    try { done.Set(); } catch (ObjectDisposedException) { }
                    if (Interlocked.Increment(ref disposeOwner) == 2) done.Dispose();
                }
            }, 1024 * 1024);

            thread.IsBackground = true;          // must never hold the process open at shutdown
            thread.Name = "pdetector-uia-probe";
            thread.Priority = ThreadPriority.BelowNormal;

            try
            {
                thread.SetApartmentState(ApartmentState.STA);
                thread.Start();
            }
            catch (Exception ex)
            {
                Interlocked.Decrement(ref _outstanding);
                try { done.Dispose(); } catch (Exception) { }
                error = ex;
                return false;
            }

            try
            {
                if (!done.Wait(timeout))
                {
                    // Abandoned. The thread may stay blocked inside COM until the process exits.
                    // We do NOT abort it - see the class remarks.
                    Interlocked.Increment(ref _totalTimeouts);
                    int inARow = Interlocked.Increment(ref _consecutiveTimeouts);

                    string message =
                        "A browser UI Automation probe did not answer within " +
                        ((int)timeout.TotalMilliseconds).ToString(System.Globalization.CultureInfo.InvariantCulture) +
                        " ms and was abandoned.";

                    // The cooldown is started ONLY once the circuit actually trips. Starting it on
                    // every timeout would mean one slow window disabled tab reading for every
                    // other window on the desktop - measured live: a single busy Chrome window
                    // timed out once and locked out three healthy windows that were answering in
                    // 200 ms. One timeout is a busy window; a run of them is a wedged browser.
                    if (inARow >= _maxConsecutiveTimeouts || Volatile.Read(ref _outstanding) >= _maxAbandonedThreads)
                    {
                        Interlocked.Exchange(ref _cooldownUntilTicks, DateTime.UtcNow.Add(_cooldown).Ticks);

                        lock (_reasonLock)
                        {
                            if (_circuitReason == null)
                            {
                                int hung = Volatile.Read(ref _outstanding);
                                string cause = inARow >= _maxConsecutiveTimeouts
                                    ? inARow.ToString(System.Globalization.CultureInfo.InvariantCulture) +
                                      " UI Automation probes in a row hung"
                                    : hung.ToString(System.Globalization.CultureInfo.InvariantCulture) +
                                      " UI Automation probes were left hung inside the browser";

                                _circuitReason =
                                    "Browser tab reading was stopped after " + cause + " (" +
                                    ((int)timeout.TotalMilliseconds).ToString(System.Globalization.CultureInfo.InvariantCulture) +
                                    " ms each). Tab and address-bar contents were NOT read for the " +
                                    "remaining browser windows; that is an unexamined area, not a clean result.";
                            }
                        }
                    }

                    error = new TimeoutException(message);
                    return false;
                }

                // A probe that answered - even one that answered with an exception - proves the
                // browser is talking to us, so the consecutive-hang counter resets.
                Interlocked.Exchange(ref _consecutiveTimeouts, 0);

                if (capturedError != null)
                {
                    error = capturedError;
                    return false;
                }

                result = captured;
                return true;
            }
            catch (Exception ex)
            {
                error = ex;
                return false;
            }
            finally
            {
                if (Interlocked.Increment(ref disposeOwner) == 2)
                {
                    try { done.Dispose(); } catch (Exception) { }
                }
            }
        }
    }
}
