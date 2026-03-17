"""
app.py - NetTrace (Beautiful Idea #1 UI + Live Capture from Idea #2)
- Stunning dark-themed forensic dashboard
- Offline PCAP upload analysis
- Real-time live packet capture (packets auto-saved to live_capture.pcap)
- Communication Proof tab with local peer detection
"""

import dash
from dash import dcc, html, Input, Output, State, callback
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import networkx as nx
import base64
import tempfile
import os
from datetime import datetime
import json  

from capture_parser import PCAPParser
from flow_analyzer import FlowAnalyzer, BehaviorProfiler
from live_capture import LiveCapture

# ────────────────────────────────────────────────
# Initialize Dash app
# ────────────────────────────────────────────────

app = dash.Dash(__name__)
app.title = "NetTrace - Forensic & Live Monitor"

live_capture = LiveCapture()

# ────────────────────────────────────────────────
# Color scheme (from your polished first version)
# ────────────────────────────────────────────────

COLORS = {
    'primary': '#0f172a',
    'secondary': '#1e293b',
    'accent': '#0ea5e9',
    'accent_alt': '#06b6d4',
    'success': '#10b981',
    'warning': '#f59e0b',
    'danger': '#ef4444',
    'surface': '#1a2e4a',
    'surface_light': '#334155',
    'text': '#f1f5f9',
    'text_dim': '#cbd5e1',
}

# ────────────────────────────────────────────────
# Layout
# ────────────────────────────────────────────────

app.layout = html.Div([
    # Header
    html.Div([
        html.Div([
            html.H1("⚡ NetTrace", style={
                'margin': '0',
                'fontSize': '2.8rem',
                'fontWeight': '800',
                'background': f'linear-gradient(135deg, {COLORS["accent"]} 0%, {COLORS["accent_alt"]} 100%)',
                'WebkitBackgroundClip': 'text',
                'WebkitTextFillColor': 'transparent',
            }),
            html.P("Forensic Network Analysis • Live Monitoring • Metadata Intelligence",
                   style={'color': COLORS['text_dim'], 'margin': '8px 0 0 0', 'fontSize': '1rem'})
        ]),
        html.Div(id='status-message', style={
            'textAlign': 'right',
            'color': COLORS['text_dim'],
            'fontSize': '0.95rem',
            'padding': '12px 18px',
            'borderRadius': '10px',
            'backgroundColor': 'rgba(14, 165, 233, 0.12)',
            'border': f'1px solid {COLORS["accent"]}'
        })
    ], style={
        'backgroundColor': COLORS['primary'],
        'borderBottom': f'2px solid {COLORS["accent"]}',
        'padding': '25px 40px',
        'display': 'flex',
        'justifyContent': 'space-between',
        'alignItems': 'center',
        'boxShadow': '0 4px 20px rgba(0,0,0,0.4)'
    }),

    # Controls
    html.Div([
        dcc.Upload(
            id='upload-pcap',
            children=html.Div([
                html.Div("📤", style={'fontSize': '3.5rem', 'margin': '0 auto 15px'}),
                html.H3("Drop PCAP File or Click to Upload", style={'color': COLORS['text'], 'margin': '0'}),
                html.P("Offline forensic analysis", style={'color': COLORS['text_dim'], 'fontSize': '0.9rem'})
            ]),
            style={
                'width': '100%', 'maxWidth': '600px', 'height': '220px',
                'border': f'2px dashed {COLORS["accent"]}', 'borderRadius': '16px',
                'textAlign': 'center', 'padding': '40px', 'margin': '30px auto',
                'backgroundColor': 'rgba(14,165,233,0.04)'
            }
        ),

        html.Div([
            html.Button("▶ Start Live Capture", id='start-live', n_clicks=0,
                        style={'background': COLORS['success'], 'color': 'white', 'padding': '14px 28px',
                               'border': 'none', 'borderRadius': '10px', 'fontWeight': '600', 'fontSize': '1.1rem',
                               'marginRight': '20px', 'cursor': 'pointer'}),
            html.Button("⏹ Stop & Save", id='stop-live', n_clicks=0,
                        style={'background': COLORS['danger'], 'color': 'white', 'padding': '14px 28px',
                               'border': 'none', 'borderRadius': '10px', 'fontWeight': '600', 'fontSize': '1.1rem',
                               'cursor': 'pointer'})
        ], style={'textAlign': 'center', 'margin': '20px 0 40px 0'})
    ]),

    dcc.Interval(id='live-update', interval=1000, n_intervals=0, disabled=True),

    # Data stores
    dcc.Store(id='flow-data'),
    dcc.Store(id='profile-data'),
    dcc.Store(id='conversation-data'),
    dcc.Store(id='apps-data'),
    dcc.Store(id='packet-pointer', data=0),

    # Tabs
    dcc.Tabs(id="tabs", value='tab-proof', children=[
        dcc.Tab(label='🎯 Communication Proof', value='tab-proof'),
        dcc.Tab(label='📊 Flows', value='tab-flows'),
        dcc.Tab(label='👤 Profiles', value='tab-profiles'),
        dcc.Tab(label='🌐 Topology', value='tab-topology'),
    ], style={'margin': '0 40px'}),

    html.Div(id='tab-content', style={'padding': '30px 40px'})
], style={'backgroundColor': COLORS['primary'], 'minHeight': '100vh', 'color': COLORS['text']})

# ────────────────────────────────────────────────
# Helper render functions (from your first polished version)
# ────────────────────────────────────────────────

def create_stat_card(title, value, icon=None, color=COLORS['accent']):
    return html.Div([
        html.Div([
            html.Span(icon or "📊", style={'fontSize': '1.8rem', 'marginRight': '12px'}),
            html.H4(title, style={'margin': '0', 'fontSize': '1.1rem', 'color': COLORS['text_dim']}),
        ], style={'display': 'flex', 'alignItems': 'center', 'marginBottom': '12px'}),
        html.H2(value, style={'margin': '0', 'color': color, 'fontSize': '2.2rem'})
    ], style={
        'backgroundColor': COLORS['surface'],
        'padding': '24px',
        'borderRadius': '12px',
        'border': f'1px solid {COLORS["surface_light"]}',
        'boxShadow': '0 4px 15px rgba(0,0,0,0.3)',
        'flex': '1',
        'minWidth': '220px'
    })


def create_app_badge(app_name):
    colors = {
        'whatsapp': '#25D366',
        'telegram': '#0088cc',
        'signal': '#3A76F0',
        'discord': '#5865F2',
        'messenger': '#0084FF',
        'unknown': COLORS['text_dim']
    }
    bg = colors.get(app_name.lower(), COLORS['surface_light'])
    return html.Span(app_name.capitalize(), style={
        'backgroundColor': bg,
        'color': 'white' if bg != COLORS['surface_light'] else COLORS['text'],
        'padding': '6px 14px',
        'borderRadius': '20px',
        'fontSize': '0.85rem',
        'fontWeight': '500',
        'marginRight': '8px'
    })


def create_conversation_card(conv):
    is_local = conv.get('is_local_both', False)
    involves_peer = conv.get('involves_peer', False)
    border_color = COLORS['success'] if is_local else COLORS['surface_light']
    badge = html.Span("LOCAL PEER", style={
        'backgroundColor': COLORS['success'],
        'color': 'white',
        'padding': '4px 10px',
        'borderRadius': '12px',
        'fontSize': '0.8rem',
        'fontWeight': '600',
        'marginLeft': '10px'
    }) if is_local or involves_peer else ""

    duration_str = f"{int(conv['duration']/60)} min {int(conv['duration']%60)} s" if conv['duration'] > 60 else f"{int(conv['duration'])} s"

    return html.Div([
        html.Div([
            html.Strong(f"{conv['ip_a']} ↔ {conv['ip_b']}"),
            badge
        ], style={'fontSize': '1.15rem', 'marginBottom': '12px', 'display': 'flex', 'alignItems': 'center'}),

        html.Div([
            html.Span(f"📦 {conv['packet_count']} packets", style={'marginRight': '20px'}),
            html.Span(f"📏 {conv['bytes_transferred']/1024:.1f} KB", style={'marginRight': '20px'}),
            html.Span(f"⏱ {duration_str}"),
        ], style={'color': COLORS['text_dim'], 'marginBottom': '12px'}),

        html.Div([
            create_app_badge(conv.get('app_used', 'unknown')),
        ], style={'marginBottom': '12px'}),

        html.Div([
            html.Small(f"First: {datetime.fromtimestamp(conv['first_seen']).strftime('%H:%M:%S')}",
                       style={'color': COLORS['text_dim'], 'marginRight': '20px'}),
            html.Small(f"Last: {datetime.fromtimestamp(conv['last_seen']).strftime('%H:%M:%S')}",
                       style={'color': COLORS['text_dim']}),
        ])
    ], style={
        'backgroundColor': COLORS['surface'],
        'padding': '20px',
        'borderRadius': '12px',
        'borderLeft': f'4px solid {border_color}',
        'marginBottom': '16px',
        'boxShadow': '0 2px 10px rgba(0,0,0,0.25)'
    })


def create_data_table(df, max_rows=12):
    if df.empty:
        return html.Div("No data yet", style={'textAlign': 'center', 'padding': '40px', 'color': COLORS['text_dim']})

    return html.Div([
        html.Table([
            html.Thead(html.Tr([
                html.Th(col, style={
                    'backgroundColor': COLORS['surface_light'],
                    'padding': '12px 16px',
                    'textAlign': 'left',
                    'color': COLORS['accent'],
                    'fontWeight': '600'
                }) for col in df.columns
            ])),
            html.Tbody([
                html.Tr([
                    html.Td(str(row[col])[:45] + '...' if len(str(row[col])) > 45 else str(row[col]),
                            style={'padding': '12px 16px', 'borderBottom': f'1px solid {COLORS["surface_light"]}'})
                    for col in df.columns
                ]) for _, row in df.head(max_rows).iterrows()
            ])
        ], style={'width': '100%', 'borderCollapse': 'collapse'})
    ], style={'overflowX': 'auto', 'backgroundColor': COLORS['surface'], 'borderRadius': '10px', 'border': f'1px solid {COLORS["surface_light"]}'})

# ────────────────────────────────────────────────
# Tab content callbacks
# ────────────────────────────────────────────────

@callback(
    Output('tab-content', 'children'),
    Input('tabs', 'value'),
    Input('flow-data', 'data'),
    Input('profile-data', 'data'),
    Input('conversation-data', 'data'),
    Input('apps-data', 'data')
)
def render_tab(tab, flow_json, profile_json, conv_json, apps_json):
    if not flow_json:
        return html.Div("Upload a PCAP file or start live capture to begin analysis.",
                        style={'textAlign': 'center', 'padding': '80px 0', 'fontSize': '1.3rem', 'color': COLORS['text_dim']})

    flow_df = pd.DataFrame(flow_json) if flow_json else pd.DataFrame()
    profile_df = pd.DataFrame(profile_json) if profile_json else pd.DataFrame()
    conv_df = pd.DataFrame(conv_json) if conv_json else pd.DataFrame()
    apps = apps_json or {}

    if tab == 'tab-proof':
        cards = []
        if not conv_df.empty:
            local_convs = conv_df[conv_df['is_local_both'] | conv_df.get('involves_peer', False)]
            local_peers = conv_df[
                (conv_df['is_local_both'] == True) &
                (conv_df['packet_count'] >= 3)
            ]
            for _, row in local_convs.sort_values('packet_count', ascending=False).head(6).iterrows():
                cards.append(create_conversation_card(row))

        return html.Div([
            html.H2("Local Peer Communication Proof", style={'marginBottom': '30px'}),
            html.Div([
                create_stat_card("Local Conversations", str(len(local_convs)) if 'local_convs' in locals() else "0", icon="🔗", color=COLORS['success']),
                create_stat_card("Local Devices Detected", str(len(local_peers)) if 'local_peers' in locals() else "0", icon="👥", color=COLORS['success']),
                create_stat_card("Most Active Peer Packets", str(conv_df['packet_count'].max()) if not conv_df.empty else "0", icon="📡"),
                create_stat_card("Apps Detected", ", ".join(apps.keys()) or "None", icon="📱"),
            ], style={'display': 'flex', 'gap': '25px', 'flexWrap': 'wrap', 'marginBottom': '40px'}),
            html.Div(cards) if cards else html.Div("No local peer conversations detected yet.", style={'textAlign': 'center', 'padding': '60px', 'color': COLORS['text_dim']})
        ])

    elif tab == 'tab-flows':
        fig = px.bar(
            flow_df.nlargest(12, 'total_bytes'),
            x='total_bytes',
            y='dst_ip',
            orientation='h',
            title="Top Data Transfers (Bytes)",
            color='total_bytes',
            color_continuous_scale='Blues'
        )
        fig.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)', font_color=COLORS['text'])

        return html.Div([
            dcc.Graph(figure=fig, style={'height': '550px'}),
            html.H3("All Flows", style={'margin': '30px 0 15px'}),
            create_data_table(flow_df)
        ])

    elif tab == 'tab-profiles':
        fig = px.bar(
            profile_df.sort_values('suspicious_score', ascending=False).head(10),
            x='suspicious_score',
            y='remote_ip',
            orientation='h',
            title="Most Suspicious Remote Hosts",
            color='suspicious_score',
            color_continuous_scale='Reds'
        )
        fig.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)', font_color=COLORS['text'])

        return html.Div([
            dcc.Graph(figure=fig, style={'height': '550px'}),
            html.H3("Host Behavioral Profiles", style={'margin': '30px 0 15px'}),
            create_data_table(profile_df)
        ])

    elif tab == 'tab-topology':
        if flow_df.empty:
            return html.Div("No connections to visualize yet.", style={'textAlign': 'center', 'padding': '100px'})

        G = nx.Graph()
        for _, row in flow_df.iterrows():
            if row['src_ip'] and row['dst_ip']:
                G.add_edge(row['src_ip'], row['dst_ip'], weight=row['total_bytes']/1e6)

        pos = nx.spring_layout(G, k=0.35, iterations=40)

        edge_x, edge_y = [], []
        for edge in G.edges(data=True):
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

        edge_trace = go.Scatter(x=edge_x, y=edge_y, line=dict(width=1.2, color='#94a3b8'), mode='lines')

        node_x, node_y, node_text = [], [], []
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            node_text.append(node)

        node_trace = go.Scatter(
            x=node_x, y=node_y, text=node_text, mode='markers+text',
            textposition='top center', marker=dict(size=14, color=COLORS['accent'], line=dict(width=2))
        )

        fig = go.Figure(data=[edge_trace, node_trace],
                        layout=go.Layout(
                            showlegend=False, hovermode='closest',
                            margin=dict(b=20,l=5,r=5,t=40),
                            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                            font=dict(color=COLORS['text'])
                        ))
        fig.update_xaxes(showgrid=False, zeroline=False, showticklabels=False)
        fig.update_yaxes(showgrid=False, zeroline=False, showticklabels=False)

        return dcc.Graph(figure=fig, style={'height': '700px'})

    return html.Div("Tab not found", style={'padding': '100px', 'textAlign': 'center'})

# ────────────────────────────────────────────────
# PCAP Upload callback
# ────────────────────────────────────────────────

@callback(
    [Output('flow-data', 'data'),
     Output('profile-data', 'data'),
     Output('conversation-data', 'data'),
     Output('apps-data', 'data'),
     Output('status-message', 'children'),
     Output('live-update', 'disabled')],
    Input('upload-pcap', 'contents'),
    State('upload-pcap', 'filename'),
    prevent_initial_call=True
)
def process_uploaded_pcap(contents, filename):
    if contents is None:
        return None, None, None, None, "Ready", True

    try:
        _, content_string = contents.split(',')
        decoded = base64.b64decode(content_string)

        with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
            tmp.write(decoded)
            path = tmp.name

        parser = PCAPParser(path)
        packet_df = parser.extract_metadata()
        conv_df = parser.get_conversation_pairs()
        apps = parser.identify_apps()

        analyzer = FlowAnalyzer(packet_df)
        flow_df = analyzer.reconstruct_flows()

        profiler = BehaviorProfiler(flow_df)
        profile_df = profiler.profile_remote_hosts()

        os.unlink(path)

        status = f"✅ Loaded: {len(packet_df):,} packets • {len(flow_df)} flows • {len(conv_df)} conversations"
        return (flow_df.to_dict('records'), profile_df.to_dict('records'),
                conv_df.to_dict('records'), apps, status, True)

    except Exception as e:
        return None, None, None, None, f"❌ {str(e)}", True

# ────────────────────────────────────────────────
# Live capture controls
# ────────────────────────────────────────────────

@callback(
    [Output('status-message', 'children', allow_duplicate=True),
     Output('live-update', 'disabled', allow_duplicate=True)],
    Input('start-live', 'n_clicks'),
    prevent_initial_call=True
)
def start_live_capture(n_clicks):
    if n_clicks > 0:
        live_capture.start()
        return "🟢 Live capture running • saving to live_capture.pcap", False
    return dash.no_update, dash.no_update


@callback(
    [Output('status-message', 'children', allow_duplicate=True),
     Output('live-update', 'disabled', allow_duplicate=True)],
    Input('stop-live', 'n_clicks'),
    prevent_initial_call=True
)
def stop_live_capture(n_clicks):
    if n_clicks > 0:
        live_capture.stop()
        return "🔴 Capture stopped • file saved as live_capture.pcap", True
    return dash.no_update, dash.no_update





# ────────────────────────────────────────────────
# Live data update (re-parses the growing pcap file)
# ────────────────────────────────────────────────
@callback(
    [Output('flow-data', 'data', allow_duplicate=True),
     Output('profile-data', 'data', allow_duplicate=True),
     Output('conversation-data', 'data', allow_duplicate=True),
     Output('apps-data', 'data', allow_duplicate=True),
     Output('packet-pointer', 'data'),
     Output('status-message', 'children', allow_duplicate=True)],
    Input('live-update', 'n_intervals'),
    State('packet-pointer', 'data'),
    prevent_initial_call=True
)
def update_live(n, pointer):
    new_packets, pointer = live_capture.get_new_packets(pointer)

    if not new_packets:
        raise dash.exceptions.PreventUpdate

    packet_df = pd.DataFrame(new_packets)

    # Optional: Sliding window of last 30 seconds
    import time
    current_time = time.time()
    packet_df = packet_df[packet_df["timestamp"] > current_time - 30]

    analyzer = FlowAnalyzer(packet_df)
    flow_df = analyzer.reconstruct_flows()

    profiler = BehaviorProfiler(flow_df)
    profile_df = profiler.profile_remote_hosts()

    conv_df = analyzer.find_conversations()

    # Build conversations exactly like PCAP parser
    from collections import defaultdict

    conversations = defaultdict(lambda:{
        "ip_a":"",
        "ip_b":"",
        "packet_count":0,
        "bytes_transferred":0,
        "first_seen":0,
        "last_seen":0,
        "app_used":"unknown"
    })

    for _,pkt in packet_df.iterrows():

        ip1,ip2 = sorted([pkt["src_ip"],pkt["dst_ip"]])
        key = f"{ip1}↔{ip2}"

        conv = conversations[key]

        conv["ip_a"] = ip1
        conv["ip_b"] = ip2
        conv["packet_count"] += 1
        conv["bytes_transferred"] += pkt["length"]

        ts = pkt["timestamp"]

        if conv["first_seen"] == 0:
            conv["first_seen"] = ts

        conv["last_seen"] = max(conv["last_seen"],ts)

        if conv["app_used"] == "unknown":
            conv["app_used"] = pkt["app_identified"]

    conv_df = pd.DataFrame(conversations.values())

    if not conv_df.empty:

        conv_df["duration"] = conv_df["last_seen"] - conv_df["first_seen"]

        def is_local(ip):
            return ip.startswith(("192.168.","10.","172."))

        conv_df["is_local_both"] = (
            conv_df["ip_a"].apply(is_local) &
            conv_df["ip_b"].apply(is_local)
        )

        conv_df["peer_device"] = (
            conv_df["is_local_both"] &
            (conv_df["packet_count"] >= 3)
        )

        # Add remaining columns to match PCAP parser structure
        conv_df['involves_suspect'] = False
        conv_df['involves_peer'] = False
        conv_df['is_messaging'] = conv_df['app_used'].str.contains('whatsapp|telegram|signal|messenger|discord', case=False, na=False)
        conv_df['connection_rate'] = conv_df['packet_count'] / conv_df['duration'].apply(lambda x: max(x, 1))

    else:
        conv_df = pd.DataFrame(columns=[
            'ip_a', 'ip_b', 'packet_count', 'bytes_transferred',
            'first_seen', 'last_seen', 'duration', 'app_used',
            'is_local_both', 'involves_suspect', 'involves_peer', 'is_messaging',
            'peer_device', 'connection_rate'
        ])

    apps = packet_df['app_identified'].value_counts().to_dict()

    count_str = f"{len(packet_df):,} pkts • {len(flow_df)} flows"
    status = f"🟢 LIVE • {count_str} • {datetime.now().strftime('%H:%M:%S.%f')[:-3]}"

    return (
        flow_df.to_dict('records') if not flow_df.empty else None,
        profile_df.to_dict('records') if not profile_df.empty else None,
        conv_df.to_dict('records') if not conv_df.empty else None,
        apps,
        pointer,
        status
    )

# ────────────────────────────────────────────────
# Run server
# ────────────────────────────────────────────────

if __name__ == '__main__':
    app.run_server(debug=True, host='127.0.0.1', port=8050)
