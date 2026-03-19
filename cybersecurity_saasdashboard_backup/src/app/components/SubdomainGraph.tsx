import { useCallback } from 'react';
import ReactFlow, {
  Node,
  Edge,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  MarkerType,
} from 'reactflow';
import 'reactflow/dist/style.css';

const initialNodes: Node[] = [
  {
    id: '1',
    type: 'default',
    data: { label: 'example.com' },
    position: { x: 250, y: 50 },
    style: {
      background: 'linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%)',
      color: 'white',
      border: 'none',
      borderRadius: '12px',
      padding: '12px 20px',
      fontWeight: 600,
      boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)',
    },
  },
  {
    id: '2',
    data: { label: 'api.example.com' },
    position: { x: 100, y: 150 },
    style: {
      background: 'white',
      color: '#1f2937',
      border: '2px solid #e5e7eb',
      borderRadius: '12px',
      padding: '10px 16px',
      boxShadow: '0 2px 4px rgba(0, 0, 0, 0.05)',
    },
  },
  {
    id: '3',
    data: { label: 'app.example.com' },
    position: { x: 250, y: 150 },
    style: {
      background: 'white',
      color: '#1f2937',
      border: '2px solid #e5e7eb',
      borderRadius: '12px',
      padding: '10px 16px',
      boxShadow: '0 2px 4px rgba(0, 0, 0, 0.05)',
    },
  },
  {
    id: '4',
    data: { label: 'cdn.example.com' },
    position: { x: 400, y: 150 },
    style: {
      background: 'white',
      color: '#1f2937',
      border: '2px solid #e5e7eb',
      borderRadius: '12px',
      padding: '10px 16px',
      boxShadow: '0 2px 4px rgba(0, 0, 0, 0.05)',
    },
  },
  {
    id: '5',
    data: { label: 'staging.api.example.com' },
    position: { x: 50, y: 250 },
    style: {
      background: '#fef3c7',
      color: '#92400e',
      border: '2px solid #fbbf24',
      borderRadius: '12px',
      padding: '10px 16px',
      boxShadow: '0 2px 4px rgba(0, 0, 0, 0.05)',
    },
  },
  {
    id: '6',
    data: { label: 'dev.api.example.com' },
    position: { x: 200, y: 250 },
    style: {
      background: '#fee2e2',
      color: '#991b1b',
      border: '2px solid #ef4444',
      borderRadius: '12px',
      padding: '10px 16px',
      boxShadow: '0 2px 4px rgba(0, 0, 0, 0.05)',
    },
  },
  {
    id: '7',
    data: { label: 'admin.app.example.com' },
    position: { x: 250, y: 250 },
    style: {
      background: '#fee2e2',
      color: '#991b1b',
      border: '2px solid #ef4444',
      borderRadius: '12px',
      padding: '10px 16px',
      boxShadow: '0 2px 4px rgba(0, 0, 0, 0.05)',
    },
  },
  {
    id: '8',
    data: { label: 'static.cdn.example.com' },
    position: { x: 400, y: 250 },
    style: {
      background: 'white',
      color: '#1f2937',
      border: '2px solid #e5e7eb',
      borderRadius: '12px',
      padding: '10px 16px',
      boxShadow: '0 2px 4px rgba(0, 0, 0, 0.05)',
    },
  },
];

const initialEdges: Edge[] = [
  {
    id: 'e1-2',
    source: '1',
    target: '2',
    animated: true,
    style: { stroke: '#3b82f6', strokeWidth: 2 },
    markerEnd: { type: MarkerType.ArrowClosed, color: '#3b82f6' },
  },
  {
    id: 'e1-3',
    source: '1',
    target: '3',
    animated: true,
    style: { stroke: '#3b82f6', strokeWidth: 2 },
    markerEnd: { type: MarkerType.ArrowClosed, color: '#3b82f6' },
  },
  {
    id: 'e1-4',
    source: '1',
    target: '4',
    animated: true,
    style: { stroke: '#3b82f6', strokeWidth: 2 },
    markerEnd: { type: MarkerType.ArrowClosed, color: '#3b82f6' },
  },
  {
    id: 'e2-5',
    source: '2',
    target: '5',
    style: { stroke: '#9ca3af', strokeWidth: 1.5 },
    markerEnd: { type: MarkerType.ArrowClosed, color: '#9ca3af' },
  },
  {
    id: 'e2-6',
    source: '2',
    target: '6',
    style: { stroke: '#ef4444', strokeWidth: 2 },
    markerEnd: { type: MarkerType.ArrowClosed, color: '#ef4444' },
  },
  {
    id: 'e3-7',
    source: '3',
    target: '7',
    style: { stroke: '#ef4444', strokeWidth: 2 },
    markerEnd: { type: MarkerType.ArrowClosed, color: '#ef4444' },
  },
  {
    id: 'e4-8',
    source: '4',
    target: '8',
    style: { stroke: '#9ca3af', strokeWidth: 1.5 },
    markerEnd: { type: MarkerType.ArrowClosed, color: '#9ca3af' },
  },
];

export default function SubdomainGraph() {
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      fitView
      attributionPosition="bottom-left"
    >
      <Background color="#e5e7eb" gap={16} />
      <Controls />
      <MiniMap
        nodeColor={(node) => {
          if (node.style?.background) {
            if (typeof node.style.background === 'string' && node.style.background.includes('gradient')) {
              return '#3b82f6';
            }
            if (node.style.background === '#fee2e2') return '#ef4444';
            if (node.style.background === '#fef3c7') return '#eab308';
          }
          return '#9ca3af';
        }}
        maskColor="rgba(0, 0, 0, 0.1)"
        style={{
          background: 'white',
          border: '2px solid #e5e7eb',
          borderRadius: '12px',
        }}
      />
    </ReactFlow>
  );
}
