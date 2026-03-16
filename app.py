"""
app.py - NetTrace Enhanced Dashboard
Modern, professional forensic analysis tool with stunning UI
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

from capture_parser import PCAPParser
from flow_analyzer import FlowAnalyzer, BehaviorProfiler

# Initialize Dash app
app = dash.Dash(__name__)
app.title = "NetTrace - Forensic Analysis"

# Define color scheme
COLORS = {
    'primary': '#0f172a',      # Dark navy
    'secondary': '#1e293b',    # Slate
    'accent': '#0ea5e9',       # Sky blue
    'accent_alt': '#06b6d4',   # Cyan
    'success': '#10b981',      # Green
    'warning': '#f59e0b',      # Amber
    'danger': '#ef4444',       # Red
    'surface': '#1a2e4a',      # Dark blue
    'surface_light': '#334155', # Light slate
    'text': '#f1f5f9',         # Off-white
    'text_dim': '#cbd5e1',     # Dim text
}

app.layout = html.Div([
    # Header Section
    html.Div([
        html.Div([
            html.Div([
                html.H1("⚡ NetTrace", style={
                    'margin': '0',
                    'fontSize': '2.5rem',
                    'fontWeight': '800',
                    'background': f'linear-gradient(135deg, {COLORS["accent"]} 0%, {COLORS["accent_alt"]} 100%)',
                    'WebkitBackgroundClip': 'text',
                    'WebkitTextFillColor': 'transparent',
                    'backgroundClip': 'text',
                    'letterSpacing': '-1px'
                }),
                html.P("Forensic Network Analysis & Metadata Intelligence", style={
                    'margin': '8px 0 0 0',
                    'color': COLORS['text_dim'],
                    'fontSize': '0.95rem',
                    'fontWeight': '500'
                })
            ]),
            html.Div(id='status-message', style={
                'textAlign': 'right',
                'color': COLORS['text_dim'],
                'fontSize': '0.9rem',
                'padding': '10px 15px',
                'borderRadius': '8px',
                'backgroundColor': f'rgba(10, 165, 233, 0.1)',
                'border': f'1px solid {COLORS["accent"]}'
            })
        ], style={
            'display': 'flex',
            'justifyContent': 'space-between',
            'alignItems': 'center',
            'padding': '30px',
            'flexWrap': 'wrap',
            'gap': '20px'
        })
    ], style={
        'backgroundColor': COLORS['primary'],
        'borderBottom': f'2px solid {COLORS["accent"]}',
        'boxShadow': f'0 10px 30px rgba(15, 23, 42, 0.5)'
    }),

    # Upload Section
    html.Div([
        html.Div([
            dcc.Upload(
                id='upload-pcap',
                children=html.Div([
                    html.Div("📤", style={
                        'fontSize': '3rem',
                        'margin': '0 auto 12px auto',
                        'display': 'block'
                    }),
                    html.H3("Drop PCAP File Here", style={
                        'margin': '12px 0 0 0',
                        'color': COLORS['text'],
                        'fontSize': '1.2rem'
                    }),
                    html.P("or click to select from your device", style={
                        'margin': '8px 0 0 0',
                        'color': COLORS['text_dim'],
                        'fontSize': '0.95rem'
                    })
                ]),
                style={
                    'width': '100%',
                    'height': '200px',
                    'borderWidth': '2px',
                    'borderStyle': 'dashed',
                    'borderRadius': '16px',
                    'textAlign': 'center',
                    'borderColor': COLORS['accent'],
                    'backgroundColor': f'rgba(15, 165, 233, 0.05)',
                    'cursor': 'pointer',
                    'transition': 'all 0.3s ease',
                    'display': 'flex',
                    'alignItems': 'center',
                    'justifyContent': 'center',
                    'flexDirection': 'column',
                    'paddingTop': '20px'
                },
                multiple=False
            ),
        ], style={'width': '100%', 'maxWidth': '700px', 'margin': '0 auto'})
    ], style={
        'padding': '40px 30px',
        'backgroundColor': COLORS['secondary'],
        'textAlign': 'center'
    }),

    # Data Stores
    dcc.Store(id='flow-data'),
    dcc.Store(id='profile-data'),
    dcc.Store(id='conversation-data'),
    dcc.Store(id='apps-data'),

    # Tabs Section
    html.Div([
        dcc.Tabs(
            id='tabs',
            value='tab-proof',
            children=[
                dcc.Tab(
                    label='🎯 Communication Proof',
                    value='tab-proof',
                    children=[html.Div(id='tab-content-proof')],
                    style={
                        'padding': '20px',
                        'backgroundColor': COLORS['primary'],
                        'color': COLORS['text']
                    },
                    selected_style={
                        'backgroundColor': COLORS['primary'],
                        'color': COLORS['accent'],
                        'borderBottom': f'3px solid {COLORS["accent"]}'
                    }
                ),
                dcc.Tab(
                    label='📊 Flow Analysis',
                    value='tab-flows',
                    children=[html.Div(id='tab-content-flows')],
                    style={
                        'padding': '20px',
                        'backgroundColor': COLORS['primary'],
                        'color': COLORS['text']
                    },
                    selected_style={
                        'backgroundColor': COLORS['primary'],
                        'color': COLORS['accent'],
                        'borderBottom': f'3px solid {COLORS["accent"]}'
                    }
                ),
                dcc.Tab(
                    label='👤 Host Profiles',
                    value='tab-profiles',
                    children=[html.Div(id='tab-content-profiles')],
                    style={
                        'padding': '20px',
                        'backgroundColor': COLORS['primary'],
                        'color': COLORS['text']
                    },
                    selected_style={
                        'backgroundColor': COLORS['primary'],
                        'color': COLORS['accent'],
                        'borderBottom': f'3px solid {COLORS["accent"]}'
                    }
                ),
                dcc.Tab(
                    label='🌐 Network Topology',
                    value='tab-graph',
                    children=[html.Div(id='tab-content-graph')],
                    style={
                        'padding': '20px',
                        'backgroundColor': COLORS['primary'],
                        'color': COLORS['text']
                    },
                    selected_style={
                        'backgroundColor': COLORS['primary'],
                        'color': COLORS['accent'],
                        'borderBottom': f'3px solid {COLORS["accent"]}'
                    }
                ),
            ],
            style={
                'backgroundColor': COLORS['primary'],
                'borderBottom': f'1px solid {COLORS["surface_light"]}'
            }
        )
    ], style={
        'backgroundColor': COLORS['primary']
    }),

    # Main Content Area
    html.Div(
        id='main-content',
        style={
            'backgroundColor': COLORS['primary'],
            'color': COLORS['text'],
            'padding': '30px',
            'minHeight': '600px'
        }
    )
], style={
    'backgroundColor': COLORS['primary'],
    'fontFamily': '"Segoe UI", Roboto, "Helvetica Neue", sans-serif',
    'color': COLORS['text'],
    'margin': '0',
    'padding': '0'
})

# Callbacks
@app.callback(
    [Output('flow-data', 'data'),
     Output('profile-data', 'data'),
     Output('conversation-data', 'data'),
     Output('apps-data', 'data'),
     Output('status-message', 'children')],
    Input('upload-pcap', 'contents'),
    State('upload-pcap', 'filename'),
    prevent_initial_call=True
)
def process_pcap(contents, filename):
    if contents is None:
        return None, None, None, None, ""
    
    try:
        content_type, content_string = contents.split(',')
        decoded = base64.b64decode(content_string)

        with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
            tmp.write(decoded)
            tmp_path = tmp.name

        parser = PCAPParser(tmp_path)
        packet_df = parser.extract_metadata()
        
        if packet_df.empty:
            os.unlink(tmp_path)
            return None, None, None, None, "❌ No IP packets found in capture"
        
        apps_detected = parser.identify_apps()
        conversations_df = parser.get_conversation_pairs()

        analyzer = FlowAnalyzer(packet_df)
        flow_df = analyzer.reconstruct_flows()

        profiler = BehaviorProfiler(flow_df)
        profiles_df = profiler.profile_remote_hosts()

        os.unlink(tmp_path)

        status = f"✅ {len(packet_df):,} packets | {len(flow_df)} flows"
        if apps_detected:
            status += f" | Apps: {', '.join(list(apps_detected.keys())[:3])}"
        
        return (flow_df.to_dict('records'), 
                profiles_df.to_dict('records'), 
                conversations_df.to_dict('records'), 
                apps_detected, 
                status)

    except Exception as e:
        return None, None, None, None, f"❌ Error: {str(e)[:50]}"


@app.callback(
    [Output('tab-content-proof', 'children'),
     Output('tab-content-flows', 'children'),
     Output('tab-content-profiles', 'children'),
     Output('tab-content-graph', 'children')],
    [Input('flow-data', 'data'),
     Input('profile-data', 'data'),
     Input('conversation-data', 'data'),
     Input('apps-data', 'data')]
)
def render_all_tabs(flow_data, profile_data, conversation_data, apps_data):
    empty_state = html.Div([
        html.Div([
            html.Div("📁", style={'fontSize': '3rem', 'marginBottom': '16px'}),
            html.H3("No Data Loaded", style={'color': COLORS['text_dim'], 'marginTop': '0'}),
            html.P("Upload a PCAP file to begin analysis", style={'color': COLORS['text_dim'], 'fontSize': '0.95rem'})
        ], style={
            'textAlign': 'center',
            'padding': '60px 30px',
            'color': COLORS['text_dim']
        })
    ])
    
    if not flow_data:
        return empty_state, empty_state, empty_state, empty_state

    flow_df = pd.DataFrame(flow_data)
    profiles_df = pd.DataFrame(profile_data) if profile_data else pd.DataFrame()
    conversations_df = pd.DataFrame(conversation_data) if conversation_data else pd.DataFrame()
    if apps_data is None:
        apps_data = {}

    return (
        render_proof_tab(conversations_df, apps_data, flow_df),
        render_flows_tab(flow_df),
        render_profiles_tab(profiles_df, flow_df),
        render_graph_tab(flow_df)
    )


def render_proof_tab(conversations_df, apps_data, flow_df):
    """Render Communication Proof Tab"""
    app_icons = {
        'whatsapp': '📱', 'telegram': '✈️', 'signal': '🔒',
        'messenger': '💬', 'discord': '🎮', 'tiktok': '🎵'
    }
    
    if not conversations_df.empty:
        try:
            conversations_df['first_seen'] = pd.to_datetime(conversations_df['first_seen'], unit='s')
            conversations_df['last_seen'] = pd.to_datetime(conversations_df['last_seen'], unit='s')
        except:
            pass
        
        local_convs = conversations_df[conversations_df.get('is_local_both', False)] if 'is_local_both' in conversations_df.columns else pd.DataFrame()
        total_convs = len(conversations_df)
        messaging_convs = len(conversations_df[conversations_df.get('is_messaging', False)]) if 'is_messaging' in conversations_df.columns else 0
        local_count = len(local_convs)
        
        # Stats Cards
        stats = html.Div([
            create_stat_card("📡 Total Conversations", total_convs, COLORS['accent']),
            create_stat_card("💬 Messaging Flows", messaging_convs, COLORS['accent_alt']),
            create_stat_card("👥 Local Peers", local_count, COLORS['success']),
            create_stat_card("📦 Total Packets", int(conversations_df['packet_count'].sum()), COLORS['warning']),
        ], style={
            'display': 'grid',
            'gridTemplateColumns': 'repeat(auto-fit, minmax(200px, 1fr))',
            'gap': '20px',
            'marginBottom': '40px'
        })
        
        # Apps Section
        apps_html = html.Div([
            html.H3("Identified Applications", style={'color': COLORS['accent'], 'marginTop': '0'}),
            html.Div([
                create_app_badge(app, app_icons.get(app, '📱'), count)
                for app, count in apps_data.items()
            ] if apps_data else [html.P("No applications identified")], style={
                'display': 'flex',
                'flexWrap': 'wrap',
                'gap': '12px'
            })
        ], style={
            'backgroundColor': COLORS['surface'],
            'padding': '20px',
            'borderRadius': '12px',
            'marginBottom': '30px',
            'border': f'1px solid {COLORS["surface_light"]}'
        })
        
        # Conversation Cards
        conv_cards = []
        
        if not local_convs.empty:
            conv_cards.append(html.H3("🎯 Local Peer Conversations", style={
                'color': COLORS['success'],
                'marginTop': '30px',
                'marginBottom': '15px'
            }))
            for _, conv in local_convs.iterrows():
                conv_cards.append(create_conversation_card(conv, app_icons, is_local=True))
        
        server_convs = conversations_df[~conversations_df.get('is_local_both', False)] if 'is_local_both' in conversations_df.columns else conversations_df
        if not server_convs.empty:
            conv_cards.append(html.H3("🌐 Server Communications", style={
                'color': COLORS['accent'],
                'marginTop': '40px',
                'marginBottom': '15px'
            }))
            for _, conv in server_convs.iterrows():
                conv_cards.append(create_conversation_card(conv, app_icons, is_local=False))
        
        return html.Div([stats, apps_html] + conv_cards)
    
    else:
        return html.Div([
            html.H3("No Conversations Detected", style={'color': COLORS['text_dim']}),
            html.P("Try capturing actual messaging traffic")
        ], style={'textAlign': 'center', 'padding': '40px'})


def render_flows_tab(flow_df):
    """Render Flow Analysis Tab with beautiful visualization"""
    if flow_df.empty:
        return html.Div("No flow data", style={'textAlign': 'center', 'padding': '40px'})
    
    # Top flows by bytes
    top_flows = flow_df.nlargest(10, 'total_bytes')[['src_ip', 'dst_ip', 'app', 'total_bytes', 'packet_count']]
    
    fig_bytes = go.Figure(data=[
        go.Bar(
            x=top_flows['total_bytes'],
            y=[f"{row['src_ip'][:12]} → {row['dst_ip'][:12]}" for _, row in top_flows.iterrows()],
            orientation='h',
            marker_color=COLORS['accent'],
            hovertemplate='<b>%{y}</b><br>Bytes: %{x:,.0f}<extra></extra>'
        )
    ])
    fig_bytes.update_layout(
        title='Top Flows by Bytes Transferred',
        xaxis_title='Bytes',
        yaxis_title='',
        template='plotly_dark',
        plot_bgcolor=COLORS['surface'],
        paper_bgcolor=COLORS['primary'],
        font_color=COLORS['text'],
        height=400,
        margin=dict(l=150, r=20, t=40, b=40)
    )
    
    # Protocol distribution
    proto_dist = flow_df['protocol'].value_counts()
    fig_proto = px.pie(
        values=proto_dist.values,
        names=proto_dist.index,
        title='Protocol Distribution',
        color_discrete_sequence=[COLORS['accent'], COLORS['accent_alt'], COLORS['success'], COLORS['warning']]
    )
    fig_proto.update_layout(
        template='plotly_dark',
        plot_bgcolor=COLORS['surface'],
        paper_bgcolor=COLORS['primary'],
        font_color=COLORS['text']
    )
    
    return html.Div([
        html.Div([
            html.Div([dcc.Graph(figure=fig_bytes)], style={'width': '48%', 'display': 'inline-block'}),
            html.Div([dcc.Graph(figure=fig_proto)], style={'width': '48%', 'display': 'inline-block', 'marginLeft': '2%'})
        ]),
        html.H3("Flow Details", style={'color': COLORS['accent'], 'marginTop': '30px'}),
        create_data_table(flow_df[['src_ip', 'dst_ip', 'app', 'total_bytes', 'packet_count', 'duration']].head(20))
    ], style={'padding': '10px'})


def render_profiles_tab(profiles_df, flow_df):
    """Render Host Profiles Tab"""
    if profiles_df.empty:
        return html.Div("No profile data", style={'textAlign': 'center', 'padding': '40px'})
    
    # Suspicious score chart
    top_suspicious = profiles_df.nlargest(8, 'suspicious_score')
    fig_sus = go.Figure(data=[
        go.Bar(
            x=top_suspicious['suspicious_score'],
            y=top_suspicious['remote_ip'],
            orientation='h',
            marker_color=[COLORS['danger'] if x > 70 else COLORS['warning'] if x > 40 else COLORS['success'] 
                         for x in top_suspicious['suspicious_score']],
            hovertemplate='<b>%{y}</b><br>Suspicion Score: %{x:.0f}<extra></extra>'
        )
    ])
    fig_sus.update_layout(
        title='Top Suspicious Hosts',
        xaxis_title='Suspicion Score',
        yaxis_title='',
        template='plotly_dark',
        plot_bgcolor=COLORS['surface'],
        paper_bgcolor=COLORS['primary'],
        font_color=COLORS['text'],
        height=400,
        margin=dict(l=150, r=20, t=40, b=40)
    )
    
    # Activity distribution
    fig_activity = go.Figure(data=[
        go.Bar(
            x=profiles_df.nlargest(10, 'total_sessions')['remote_ip'],
            y=profiles_df.nlargest(10, 'total_sessions')['total_sessions'],
            marker_color=COLORS['accent_alt'],
            hovertemplate='<b>%{x}</b><br>Sessions: %{y}<extra></extra>'
        )
    ])
    fig_activity.update_layout(
        title='Most Active Remote Hosts',
        xaxis_title='Remote IP',
        yaxis_title='Number of Sessions',
        template='plotly_dark',
        plot_bgcolor=COLORS['surface'],
        paper_bgcolor=COLORS['primary'],
        font_color=COLORS['text'],
        xaxis_tickangle=-45,
        height=400,
        margin=dict(l=60, r=20, t=40, b=80)
    )
    
    return html.Div([
        html.Div([
            html.Div([dcc.Graph(figure=fig_sus)], style={'width': '48%', 'display': 'inline-block'}),
            html.Div([dcc.Graph(figure=fig_activity)], style={'width': '48%', 'display': 'inline-block', 'marginLeft': '2%'})
        ]),
        html.H3("Host Profiles", style={'color': COLORS['accent'], 'marginTop': '30px'}),
        create_data_table(profiles_df[['remote_ip', 'total_sessions', 'total_bytes', 'communication_regularity', 'suspicious_score']].head(15))
    ], style={'padding': '10px'})


def render_graph_tab(flow_df):
    """Render Network Topology Visualization"""
    if flow_df.empty:
        return html.Div("No data for graph", style={'textAlign': 'center', 'padding': '40px'})
    
    try:
        G = nx.Graph()
        
        for _, flow in flow_df.iterrows():
            src = flow.get('src_ip', '')
            dst = flow.get('dst_ip', '')
            if src and dst:
                weight = flow.get('total_bytes', 0) / 1000
                G.add_edge(src, dst, weight=weight, app=flow.get('app', 'unknown'))
        
        if len(G.nodes()) == 0:
            return html.Div("No data for graph", style={'textAlign': 'center', 'padding': '40px'})
        
        pos = nx.spring_layout(G, k=2, iterations=50, seed=42)
        
        edge_x = []
        edge_y = []
        for u, v, d in G.edges(data=True):
            if u in pos and v in pos:
                x0, y0 = pos[u]
                x1, y1 = pos[v]
                edge_x.extend([x0, x1, None])
                edge_y.extend([y0, y1, None])
        
        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            mode='lines',
            line=dict(width=0.5, color=f'rgba(255,255,255,0.2)'),
            hoverinfo='none',
            showlegend=False
        )
        
        node_x = [pos[n][0] for n in G.nodes()]
        node_y = [pos[n][1] for n in G.nodes()]
        node_text = list(G.nodes())
        
        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            text=node_text,
            textposition="top center",
            textfont=dict(size=10, color=COLORS['text']),
            hoverinfo='text',
            hovertext=node_text,
            marker=dict(
                size=15,
                color=COLORS['accent'],
                line=dict(color=COLORS['accent_alt'], width=2),
                opacity=0.9
            ),
            showlegend=False
        )
        
        fig = go.Figure(data=[edge_trace, node_trace],
                       layout=go.Layout(
                           title='Network Topology Graph',
                           showlegend=False,
                           hovermode='closest',
                           margin=dict(b=20,l=5,r=5,t=40),
                           xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                           yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                           plot_bgcolor=COLORS['surface'],
                           paper_bgcolor=COLORS['primary'],
                           font_color=COLORS['text'],
                           height=700
                       ))
        return dcc.Graph(figure=fig, style={'height': '700px'})
        
    except Exception as e:
        return html.Div(f"Error rendering graph: {str(e)}", style={'color': COLORS['danger']})


# ============ Component Helpers ============

def create_stat_card(title, value, color):
    """Create a beautiful stat card"""
    return html.Div([
        html.P(title, style={'color': COLORS['text_dim'], 'margin': '0 0 12px 0', 'fontSize': '0.9rem', 'fontWeight': '600'}),
        html.H2(f"{value:,}", style={'color': color, 'margin': '0', 'fontSize': '2rem', 'fontWeight': '700'})
    ], style={
        'backgroundColor': COLORS['surface'],
        'padding': '24px',
        'borderRadius': '12px',
        'border': f'1px solid {COLORS["surface_light"]}',
        'borderLeft': f'4px solid {color}',
        'transition': 'all 0.3s ease',
        'cursor': 'pointer'
    })


def create_app_badge(app, icon, count):
    """Create an app badge"""
    return html.Div([
        html.Span(icon, style={'marginRight': '8px', 'fontSize': '1.2rem'}),
        html.Span(f"{app.title()}", style={'fontWeight': '600'}),
        html.Span(f"({count})", style={'marginLeft': '6px', 'color': COLORS['text_dim'], 'fontSize': '0.85rem'})
    ], style={
        'backgroundColor': COLORS['surface_light'],
        'color': COLORS['text'],
        'padding': '10px 16px',
        'borderRadius': '8px',
        'fontSize': '0.95rem',
        'border': f'1px solid {COLORS["accent"]}',
        'display': 'inline-flex',
        'alignItems': 'center',
        'transition': 'all 0.2s ease'
    })


def create_conversation_card(conv, app_icons, is_local=False):
    """Create a beautiful conversation card"""
    ip_a = conv.get('ip_a', 'Unknown')
    ip_b = conv.get('ip_b', 'Unknown')
    packet_count = conv.get('packet_count', 0)
    bytes_transferred = conv.get('bytes_transferred', 0)
    app_used = conv.get('app_used', 'unknown')
    
    first_seen = conv.get('first_seen', '')
    last_seen = conv.get('last_seen', '')
    
    if isinstance(first_seen, pd.Timestamp):
        first_seen_str = first_seen.strftime('%H:%M:%S')
        last_seen_str = last_seen.strftime('%H:%M:%S')
    else:
        first_seen_str = str(first_seen)[:8]
        last_seen_str = str(last_seen)[:8]
    
    # Color selection
    if is_local:
        border_color = COLORS['success']
        bg_color = f'rgba(16, 185, 129, 0.1)'
        badge_color = COLORS['success']
        badge_text = "🎯 LOCAL PEER"
    else:
        if app_used == 'whatsapp':
            border_color = '#25D366'
            badge_color = '#25D366'
        else:
            border_color = COLORS['accent']
            badge_color = COLORS['accent']
        bg_color = f'rgba(14, 165, 233, 0.1)'
        badge_text = f"{app_icons.get(app_used, '🌐')} SERVER"
    
    return html.Div([
        html.Div([
            html.Div([
                html.Span(f"{ip_a}", style={'fontFamily': 'monospace', 'fontSize': '0.9rem', 'fontWeight': '700'}),
                html.Span(" ↔ ", style={'margin': '0 8px', 'color': COLORS['text_dim']}),
                html.Span(f"{ip_b}", style={'fontFamily': 'monospace', 'fontSize': '0.9rem', 'fontWeight': '700'})
            ]),
            html.Span(badge_text, style={
                'backgroundColor': badge_color,
                'color': 'white',
                'padding': '4px 12px',
                'borderRadius': '20px',
                'fontSize': '0.8rem',
                'fontWeight': '600',
                'marginLeft': '12px'
            })
        ], style={
            'display': 'flex',
            'justifyContent': 'space-between',
            'alignItems': 'center',
            'marginBottom': '16px',
            'paddingBottom': '12px',
            'borderBottom': f'1px solid {border_color}'
        }),
        
        html.Div([
            html.Div([
                html.Div([
                    html.Span("📦 Packets", style={'color': COLORS['text_dim'], 'fontSize': '0.85rem'}),
                    html.Div(f"{packet_count}", style={'fontSize': '1.3rem', 'fontWeight': '700', 'color': COLORS['accent'], 'marginTop': '4px'})
                ], style={'textAlign': 'center'}),
                html.Div([
                    html.Span("💾 Bytes", style={'color': COLORS['text_dim'], 'fontSize': '0.85rem'}),
                    html.Div(f"{bytes_transferred/1024:.1f} KB", style={'fontSize': '1.3rem', 'fontWeight': '700', 'color': COLORS['accent_alt'], 'marginTop': '4px'})
                ], style={'textAlign': 'center'}),
                html.Div([
                    html.Span("⏱️ Duration", style={'color': COLORS['text_dim'], 'fontSize': '0.85rem'}),
                    html.Div(f"{conv.get('duration', 0):.1f}s", style={'fontSize': '1.3rem', 'fontWeight': '700', 'color': COLORS['warning'], 'marginTop': '4px'})
                ], style={'textAlign': 'center'})
            ], style={
                'display': 'flex',
                'justifyContent': 'space-around',
                'gap': '20px'
            }),
            html.Div([
                html.Span("First Seen: ", style={'color': COLORS['text_dim'], 'fontSize': '0.85rem'}),
                html.Span(first_seen_str, style={'fontFamily': 'monospace', 'fontWeight': '600'}),
                html.Br(),
                html.Span("Last Seen: ", style={'color': COLORS['text_dim'], 'fontSize': '0.85rem'}),
                html.Span(last_seen_str, style={'fontFamily': 'monospace', 'fontWeight': '600'})
            ], style={'marginTop': '12px', 'paddingTop': '12px', 'borderTop': f'1px solid {COLORS["surface_light"]}'})
        ])
    ], style={
        'border': f'2px solid {border_color}',
        'borderRadius': '12px',
        'padding': '20px',
        'margin': '15px 0',
        'backgroundColor': bg_color,
        'transition': 'all 0.3s ease'
    })


def create_data_table(df):
    """Create a styled data table"""
    if df.empty:
        return html.Div("No data", style={'textAlign': 'center', 'padding': '20px'})
    
    return html.Div([
        html.Table([
            html.Thead(
                html.Tr([
                    html.Th(col, style={
                        'backgroundColor': COLORS['surface_light'],
                        'color': COLORS['accent'],
                        'padding': '12px',
                        'textAlign': 'left',
                        'fontSize': '0.9rem',
                        'fontWeight': '600',
                        'borderBottom': f'2px solid {COLORS["accent"]}'
                    })
                    for col in df.columns
                ])
            ),
            html.Tbody([
                html.Tr([
                    html.Td(str(row[col])[:30], style={
                        'padding': '12px',
                        'borderBottom': f'1px solid {COLORS["surface_light"]}',
                        'fontSize': '0.9rem',
                        'fontFamily': 'monospace' if col.endswith('ip') else 'inherit'
                    })
                    for col in df.columns
                ])
                for _, row in df.iterrows()
            ])
        ], style={
            'width': '100%',
            'borderCollapse': 'collapse',
            'marginTop': '20px'
        })
    ], style={
        'overflowX': 'auto',
        'borderRadius': '8px',
        'border': f'1px solid {COLORS["surface_light"]}',
        'backgroundColor': COLORS['surface']
    })


# Enhanced CSS
app.index_string = '''
<!DOCTYPE html>
<html>
    <head>
        {%metas%}
        <title>{%title%}</title>
        {%favicon%}
        {%css%}
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                background-color: #0f172a;
                color: #f1f5f9;
                font-family: "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
                line-height: 1.6;
            }
            
            #react-entry-point {
                background-color: #0f172a;
            }
            
            /* Smooth animations */
            * {
                transition: background-color 0.3s ease, color 0.3s ease;
            }
            
            /* Scrollbar styling */
            ::-webkit-scrollbar {
                width: 8px;
            }
            ::-webkit-scrollbar-track {
                background: #1e293b;
            }
            ::-webkit-scrollbar-thumb {
                background: #0ea5e9;
                border-radius: 4px;
            }
            ::-webkit-scrollbar-thumb:hover {
                background: #06b6d4;
            }
            
            /* Tab styling */
            .react-tabs__tab-list {
                background-color: #0f172a !important;
                border-bottom: 1px solid #334155 !important;
            }
            
            .react-tabs__tab {
                color: #cbd5e1 !important;
                background-color: transparent !important;
            }
            
            .react-tabs__tab--selected {
                background-color: #0f172a !important;
                color: #0ea5e9 !important;
                border-bottom: 3px solid #0ea5e9 !important;
            }
            
            /* Hover effects */
            div:hover {
                transition: all 0.3s ease;
            }
        </style>
    </head>
    <body>
        {%app_entry%}
        <footer>
            {%config%}
            {%scripts%}
            {%renderer%}
        </footer>
    </body>
</html>
'''

if __name__ == '__main__':
    app.run_server(debug=True, host='127.0.0.1', port=8050)