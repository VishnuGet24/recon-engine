import { useMemo } from 'react';
import ReactFlow, { Background, Controls, MiniMap, type Edge, type Node } from 'reactflow';
import 'reactflow/dist/style.css';

import type { SubdomainMapResponse } from '../../../api/dashboard';

type Props = {
  data: SubdomainMapResponse | null;
  loading?: boolean;
};

function nodeStyle(node: SubdomainMapResponse['nodes'][number]) {
  const isRoot = node.type === 'root';
  const risk = (node.riskLevel || 'info').toLowerCase();
  const border = risk === 'high' ? '#ef4444' : isRoot ? '#2563eb' : '#16a34a';
  const background = isRoot ? '#eff6ff' : '#ecfdf5';
  const text = '#0f172a';
  return {
    border: `2px solid ${border}`,
    background,
    color: text,
    borderRadius: 12,
    padding: 10,
    width: 260,
    fontSize: 12,
  } as const;
}

export default function SubdomainGraph({ data, loading }: Props) {
  const { nodes, edges } = useMemo(() => {
    if (!data?.nodes?.length) return { nodes: [] as Node[], edges: [] as Edge[] };

    const root = data.nodes.find((n) => n.type === 'root') || data.nodes[0];
    const subs = data.nodes.filter((n) => n.id !== root.id);

    const center = { x: 0, y: 0 };
    const radius = 260;

    const rfNodes: Node[] = [];
    rfNodes.push({
      id: root.id,
      data: {
        label: (
          <div>
            <div className="font-semibold">{root.id}</div>
            <div className="mt-1 text-[11px] text-slate-700">
              IP: {root.metadata?.ipAddress || '—'} · Ports: {(root.metadata?.openPorts || []).slice(0, 8).join(', ') || '—'}
            </div>
            {root.metadata?.technologies?.length ? (
              <div className="mt-1 text-[11px] text-slate-700 truncate">
                Tech: {root.metadata.technologies.slice(0, 6).join(', ')}
              </div>
            ) : null}
          </div>
        ),
      },
      position: center,
      style: nodeStyle(root),
    });

    subs.forEach((n, idx) => {
      const angle = (idx / Math.max(1, subs.length)) * Math.PI * 2;
      const x = center.x + Math.cos(angle) * radius;
      const y = center.y + Math.sin(angle) * radius;
      rfNodes.push({
        id: n.id,
        data: {
          label: (
            <div>
              <div className="font-semibold">{n.id}</div>
              <div className="mt-1 text-[11px] text-slate-700">IP: {n.metadata?.ipAddress || '—'}</div>
            </div>
          ),
        },
        position: { x, y },
        style: nodeStyle(n),
      });
    });

    const rfEdges: Edge[] = (data.edges || []).map((e) => ({
      id: `${e.source}->${e.target}`,
      source: e.source,
      target: e.target,
      animated: false,
      style: { stroke: '#94a3b8' },
    }));

    return { nodes: rfNodes, edges: rfEdges };
  }, [data]);

  return (
    <div className="bg-white rounded-2xl p-6 shadow-sm">
      <div className="mb-4">
        <h3 className="text-lg font-semibold text-gray-900">Subdomain Relationship Graph</h3>
        <p className="text-sm text-gray-500">Derived from scan modules: subdomain_enum, dns_enum, hosting_detection</p>
      </div>

      <div className="h-[520px] rounded-2xl border border-gray-200 overflow-hidden">
        {loading ? (
          <div className="h-full flex items-center justify-center text-sm text-gray-500">Loading graph…</div>
        ) : nodes.length ? (
          <ReactFlow nodes={nodes} edges={edges} fitView minZoom={0.2} nodesDraggable={false} nodesConnectable={false}>
            <Background gap={16} color="#e5e7eb" />
            <Controls />
            <MiniMap />
          </ReactFlow>
        ) : (
          <div className="h-full flex items-center justify-center text-sm text-gray-500">No subdomain data for this scan.</div>
        )}
      </div>

      <div className="mt-3 text-xs text-gray-500">
        Colors: root (blue), subdomain (green), high-risk outline (red).
      </div>
    </div>
  );
}

