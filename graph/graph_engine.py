# graph/graph_engine.py
import time
try:
    import networkx as nx
    NX_OK = True
except ImportError:
    NX_OK = False

class SecurityGraph:
    def __init__(self):
        self.graph = nx.DiGraph() if NX_OK else None
        self._edges = []
        self._count = 0

    def add_event(self, src, dst, relation):
        src, dst = str(src)[:60], str(dst)[:60]
        if NX_OK:
            self.graph.add_edge(src, dst, relation=relation, ts=time.time())
        self._edges.append((src, dst, relation))
        self._count += 1

    def suspicious_paths(self):
        if not NX_OK or not self.graph: return []
        paths = []
        try:
            nodes = list(self.graph.nodes)[:15]
            for s in nodes:
                for d in nodes:
                    if s != d:
                        try:
                            for p in nx.all_simple_paths(self.graph, s, d, cutoff=4):
                                if len(p) >= 3:
                                    paths.append(p)
                                    if len(paths) >= 30: return paths
                        except Exception: pass
        except Exception: pass
        return paths

    def node_count(self): return self.graph.number_of_nodes() if NX_OK else len(set(s for s,d,r in self._edges))
    def edge_count(self): return self._count
