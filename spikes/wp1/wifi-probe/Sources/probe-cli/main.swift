import ProbeCore

// Plain CLI. Run from Terminal (attributed to Terminal) or spawned by ProbeApp
// (tests whether a child process inherits the app's Location authorization).
let args = Args.parse()
Probe.write(Probe.snapshot(variant: args.variant, raw: args.raw), to: args.outDir)
