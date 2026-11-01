import { createContext, useContext, useMemo, useState, type ReactNode } from "react";
import type { TimeWindow } from "../lib/ipc";
import type { TrafficFilter } from "../lib/nodeFlows";
import { defaultTopologyView, type TopologyView } from "../lib/topologyView";
import type { ScreenId } from "./nav";

/**
 * Context preservation (design §1.7): the selected asset/flow/finding and time
 * window survive switching between Topology, Traffic and Findings.
 * Skeleton: state holder only.
 */
export interface Selection {
  subjectId: string | null;
  /** Topology time window (half-open, Unix ms); null = everything. */
  timeWindow: TimeWindow | null;
  /** An address to select once Topology has its graph ("show in Topology"). */
  focusAddress: string | null;
  /** Traffic shows only these flows ("Open Traffic" from a node); null = all. */
  trafficFilter: TrafficFilter | null;
}

interface SelectionCtx {
  selection: Selection;
  setSelection: (s: Selection) => void;
  screen: ScreenId;
  setScreen: (s: ScreenId) => void;
  /** Topology overlays and zoom, kept while other screens are open. */
  topologyView: TopologyView;
  setTopologyView: (f: (v: TopologyView) => TopologyView) => void;
}

const Ctx = createContext<SelectionCtx | null>(null);

export function SelectionProvider({ children }: { children: ReactNode }) {
  const [selection, setSelection] = useState<Selection>({ subjectId: null, timeWindow: null, focusAddress: null, trafficFilter: null });
  const [screen, setScreen] = useState<ScreenId>("topology");
  const [topologyView, setTopologyView] = useState<TopologyView>(defaultTopologyView);
  const value = useMemo(() => ({ selection, setSelection, screen, setScreen, topologyView, setTopologyView }), [selection, screen, topologyView]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useSelection(): SelectionCtx {
  const v = useContext(Ctx);
  if (!v) throw new Error("useSelection outside SelectionProvider");
  return v;
}
