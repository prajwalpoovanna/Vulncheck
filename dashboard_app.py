#!/usr/bin/env python3
"""
Step 2: Complete Web Dashboard with all required features.
"""
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
from dash import Dash, dcc, html, dash_table, Input, Output, State
import dash_bootstrap_components as dbc
from flask import Flask
import json

# Load data
print("Loading vulnerability data...")
try:
    df = pd.read_csv('analysis/enriched_vulnerabilities.csv')
    print(f"✅ Loaded {len(df)} CVEs")
except FileNotFoundError:
    print("❌ No data found. Please run run_analysis.py first.")
    # Create sample data for demonstration
    df = pd.DataFrame({
        'cve_id': ['CVE-2024-3400', 'CVE-2023-34362', 'CVE-2022-34753'],
        'cvss_v3_score': [9.8, 9.1, 7.2],
        'cvss_v3_severity': ['CRITICAL', 'CRITICAL', 'HIGH'],
        'epss_score': [0.97, 0.85, 0.42],
        'priority_tier': ['Ransomware/Botnets', 'Threat Actors (APTs)', 'Proof-of-Concept'],
        'cisa_kev': [True, True, False],
        'vulncheck_kev': [True, False, False],
        'has_exploit': [True, True, True],
        'exploit_count': [3, 2, 1],
        'exploit_maturity': ['WEAPONIZED', 'WEAPONIZED', 'POC'],
        'description': ['Sample description 1', 'Sample description 2', 'Sample description 3'],
        'risk_score': [95.2, 88.7, 65.3],
        'affected_cpe': ['paloaltonetworks:pan-os', 'microsoft:windows', 'smart-hm:webig']
    })

# Initialize Dash app with Bootstrap
server = Flask(__name__)
app = Dash(__name__, server=server, external_stylesheets=[dbc.themes.BOOTSTRAP])

# Define pyramid tiers (in order from highest to lowest priority)
PYRAMID_TIERS = [
    "Ransomware/Botnets",
    "Threat Actors (APTs)", 
    "Unattributed KEV",
    "VulnCheck KEV",
    "Weaponized",
    "Proof-of-Concept",
    "All Other Vulnerabilities"
]

# Calculate statistics
def calculate_statistics():
    stats = {
        'total_cves': len(df),
        'critical_severity': len(df[df['cvss_v3_score'] >= 9.0]),
        'high_severity': len(df[df['cvss_v3_score'] >= 7.0]),
        'with_exploits': int(df['has_exploit'].sum()),
        'cisa_kev': int(df['cisa_kev'].sum()),
        'vulncheck_kev': int(df['vulncheck_kev'].sum()),
        'total_exploits': int(df['exploit_count'].sum()),
        'avg_risk_score': round(df['risk_score'].mean(), 2)
    }
    
    # Pyramid tier counts
    tier_counts = {}
    for tier in PYRAMID_TIERS:
        count = len(df[df['priority_tier'] == tier])
        tier_counts[tier] = count
    
    stats['tier_counts'] = tier_counts
    return stats

stats = calculate_statistics()

# App layout
app.layout = dbc.Container([
    # Header
    dbc.Row([
        dbc.Col([
            html.H1("VulnCheck Vulnerability Dashboard", className="text-center my-4"),
            html.P("Evidence-Based Vulnerability Prioritization for Acme Financial Services", 
                  className="text-center text-muted")
        ], width=12)
    ]),
    
    # Key Metrics Cards
    dbc.Row([
        dbc.Col(dbc.Card([
            dbc.CardBody([
                html.H4(f"{stats['total_cves']}", className="card-title text-center"),
                html.P("Total CVEs", className="card-text text-center")
            ])
        ], color="light", className="mb-4"), width=2),
        
        dbc.Col(dbc.Card([
            dbc.CardBody([
                html.H4(f"{stats['critical_severity']}", className="card-title text-center text-danger"),
                html.P("Critical (CVSS ≥ 9.0)", className="card-text text-center")
            ])
        ], color="light", className="mb-4"), width=2),
        
        dbc.Col(dbc.Card([
            dbc.CardBody([
                html.H4(f"{stats['with_exploits']}", className="card-title text-center text-warning"),
                html.P("With Exploits", className="card-text text-center")
            ])
        ], color="light", className="mb-4"), width=2),
        
        dbc.Col(dbc.Card([
            dbc.CardBody([
                html.H4(f"{stats['cisa_kev']}", className="card-title text-center text-danger"),
                html.P("CISA KEV", className="card-text text-center")
            ])
        ], color="light", className="mb-4"), width=2),
        
        dbc.Col(dbc.Card([
            dbc.CardBody([
                html.H4(f"{stats['vulncheck_kev']}", className="card-title text-center text-warning"),
                html.P("VulnCheck KEV", className="card-text text-center")
            ])
        ], color="light", className="mb-4"), width=2),
        
        dbc.Col(dbc.Card([
            dbc.CardBody([
                html.H4(f"{stats['avg_risk_score']}", className="card-title text-center text-info"),
                html.P("Avg Risk Score", className="card-text text-center")
            ])
        ], color="light", className="mb-4"), width=2),
    ]),
    
    # Prioritization Pyramid Section
    dbc.Row([
        dbc.Col([
            html.H3("Evidence-Based Vulnerability Prioritization Pyramid", className="mt-4"),
            dcc.Graph(id='pyramid-chart', style={'height': '420px'}),
            html.P("Prioritize remediation from top (most critical) to bottom", className="text-muted")
        ], width=12)
    ]),
    
    # Charts Row 1
    dbc.Row([
        dbc.Col([
            dcc.Graph(id='cvss-distribution', style={'height': '360px'})
        ], width=6),
        
        dbc.Col([
            dcc.Graph(id='exploit-maturity', style={'height': '360px'})
        ], width=6)
    ]),
    
    # Charts Row 2
    dbc.Row([
        dbc.Col([
            dcc.Graph(id='cvss-epss-scatter', style={'height': '360px'})
        ], width=6),
        
        dbc.Col([
            dcc.Graph(id='system-vulnerabilities', style={'height': '360px'})
        ], width=6)
    ]),
    
    # Interactive Data Table
    dbc.Row([
        dbc.Col([
            html.H3("Prioritized Vulnerabilities", className="mt-4"),
            html.P("Sort and filter to identify remediation priorities", className="text-muted"),
            
            # Filters
            dbc.Row([
                dbc.Col([
                    html.Label("Filter by Priority Tier:"),
                    dcc.Dropdown(
                        id='tier-filter',
                        options=[{'label': tier, 'value': tier} for tier in PYRAMID_TIERS] + [{'label': 'All', 'value': 'All'}],
                        value='All',
                        clearable=False
                    )
                ], width=4),
                
                dbc.Col([
                    html.Label("Filter by CVSS Severity:"),
                    dcc.Dropdown(
                        id='severity-filter',
                        options=[
                            {'label': 'All', 'value': 'All'},
                            {'label': 'Critical (≥9.0)', 'value': 'Critical'},
                            {'label': 'High (7.0-8.9)', 'value': 'High'},
                            {'label': 'Medium (4.0-6.9)', 'value': 'Medium'},
                            {'label': 'Low (<4.0)', 'value': 'Low'}
                        ],
                        value='All',
                        clearable=False
                    )
                ], width=4),
                
                dbc.Col([
                    html.Label("Filter by Exploit Status:"),
                    dcc.Dropdown(
                        id='exploit-filter',
                        options=[
                            {'label': 'All', 'value': 'All'},
                            {'label': 'Has Exploits', 'value': 'Has'},
                            {'label': 'No Exploits', 'value': 'No'}
                        ],
                        value='All',
                        clearable=False
                    )
                ], width=4)
            ], className="mb-3"),
            
            # Data Table
            dash_table.DataTable(
                id='vulnerability-table',
                columns=[
                    {"name": "CVE ID", "id": "cve_id"},
                    {"name": "Priority Tier", "id": "priority_tier"},
                    {"name": "CVSS Score", "id": "cvss_v3_score", "type": "numeric", "format": {"specifier": ".2f"}},
                    {"name": "CVSS Severity", "id": "cvss_v3_severity"},
                    {"name": "EPSS Score", "id": "epss_score", "type": "numeric", "format": {"specifier": ".4f"}},
                    {"name": "Risk Score", "id": "risk_score", "type": "numeric", "format": {"specifier": ".2f"}},
                    {"name": "CISA KEV", "id": "cisa_kev"},
                    {"name": "Has Exploit", "id": "has_exploit"},
                    {"name": "Exploit Count", "id": "exploit_count", "type": "numeric"},
                    {"name": "Affected System", "id": "affected_cpe"}
                ],
                data=df.to_dict('records'),
                sort_action='native',
                filter_action='native',
                page_size=15,
                style_table={'overflowX': 'auto'},
                style_cell={
                    'textAlign': 'left',
                    'padding': '10px',
                    'minWidth': '100px'
                },
                style_header={
                    'backgroundColor': 'rgb(230, 230, 230)',
                    'fontWeight': 'bold'
                },
                style_data_conditional=[
                    {
                        'if': {
                            'filter_query': '{cvss_v3_score} >= 9',
                            'column_id': 'cvss_v3_score'
                        },
                        'backgroundColor': '#ffcccc',
                        'color': 'black'
                    },
                    {
                        'if': {
                            'filter_query': '{cisa_kev} = True',
                            'column_id': 'cisa_kev'
                        },
                        'backgroundColor': '#ff9999',
                        'color': 'black'
                    }
                ]
            )
            ,
            dbc.Row([
                dbc.Col(html.Button('Download CSV', id='download-btn', className='btn btn-primary'), width='auto'),
                dcc.Download(id='download-dataframe-csv')
            ], className='mt-3')
        ], width=12)
    ]),
    
    # Footer
    dbc.Row([
        dbc.Col([
            html.Hr(),
            html.P("Generated using VulnCheck Intelligence • Data as of latest analysis", 
                  className="text-center text-muted small")
        ], width=12)
    ])
], fluid=True)

# Callback for filters
@app.callback(
    Output('vulnerability-table', 'data'),
    [Input('tier-filter', 'value'),
     Input('severity-filter', 'value'),
     Input('exploit-filter', 'value')]
)
def update_table(tier_filter, severity_filter, exploit_filter):
    filtered_df = df.copy()
    
    # Apply priority tier filter
    if tier_filter != 'All':
        filtered_df = filtered_df[filtered_df['priority_tier'] == tier_filter]
    
    # Apply severity filter
    if severity_filter != 'All':
        if severity_filter == 'Critical':
            filtered_df = filtered_df[filtered_df['cvss_v3_score'] >= 9.0]
        elif severity_filter == 'High':
            filtered_df = filtered_df[(filtered_df['cvss_v3_score'] >= 7.0) & (filtered_df['cvss_v3_score'] < 9.0)]
        elif severity_filter == 'Medium':
            filtered_df = filtered_df[(filtered_df['cvss_v3_score'] >= 4.0) & (filtered_df['cvss_v3_score'] < 7.0)]
        elif severity_filter == 'Low':
            filtered_df = filtered_df[filtered_df['cvss_v3_score'] < 4.0]
    
    # Apply exploit filter
    if exploit_filter != 'All':
        if exploit_filter == 'Has':
            filtered_df = filtered_df[filtered_df['has_exploit'] == True]
        elif exploit_filter == 'No':
            filtered_df = filtered_df[filtered_df['has_exploit'] == False]
    
    return filtered_df.to_dict('records')


# CSV download callback — exports current table data
@app.callback(
    Output('download-dataframe-csv', 'data'),
    Input('download-btn', 'n_clicks'),
    State('vulnerability-table', 'data'),
    prevent_initial_call=True
)
def download_csv(n_clicks, table_data):
    if not table_data:
        return None
    dff = pd.DataFrame(table_data)
    return dcc.send_data_frame(dff.to_csv, 'vulnerabilities_filtered.csv', index=False)

# Generate charts on startup
@app.callback(
    Output('pyramid-chart', 'figure'),
    Output('cvss-distribution', 'figure'),
    Output('exploit-maturity', 'figure'),
    Output('cvss-epss-scatter', 'figure'),
    Output('system-vulnerabilities', 'figure'),
    [Input('vulnerability-table', 'data')]
)
def update_charts(data):
    # Convert data back to DataFrame
    current_df = pd.DataFrame(data) if data else df
    
    # 1. Pyramid Chart
    tier_counts = current_df['priority_tier'].value_counts()
    # Ensure all pyramid tiers are represented
    for tier in PYRAMID_TIERS:
        if tier not in tier_counts:
            tier_counts[tier] = 0
    
    pyramid_fig = go.Figure(data=[
        go.Bar(
            x=[tier_counts.get(tier, 0) for tier in PYRAMID_TIERS],
            y=PYRAMID_TIERS,
            orientation='h',
            marker_color=['#ff0000', '#ff4500', '#ff8c00', '#ffd700', '#adff2f', '#32cd32', '#d3d3d3'],
            text=[tier_counts.get(tier, 0) for tier in PYRAMID_TIERS],
            textposition='auto'
        )
    ])
    
    pyramid_fig.update_layout(
        title="Vulnerability Prioritization Pyramid",
        xaxis_title="Number of CVEs",
        yaxis_title="Priority Tier",
        height=400,
        showlegend=False,
        template="plotly_white"
    )
    
    # 2. CVSS Distribution
    cvss_fig = px.histogram(
        current_df, 
        x='cvss_v3_score',
        nbins=20,
        title="CVSS v3 Score Distribution",
        color_discrete_sequence=['crimson']
    )
    cvss_fig.update_layout(height=350)
    
    # 3. Exploit Maturity
    exploit_counts = current_df['has_exploit'].value_counts()
    exploit_fig = px.pie(
        values=exploit_counts.values,
        names=['Has Exploits', 'No Exploits'],
        title="Exploit Availability",
        color_discrete_sequence=['red', 'green']
    )
    exploit_fig.update_layout(height=350)
    
    # 4. CVSS vs EPSS Correlation
    scatter_fig = px.scatter(
        current_df,
        x='cvss_v3_score',
        y='epss_score',
        color='priority_tier',
        hover_data=['cve_id', 'cvss_v3_severity'],
        title="CVSS vs EPSS Correlation",
        size='risk_score'
    )
    scatter_fig.update_layout(height=350)
    
    # 5. System Vulnerabilities
    if 'affected_cpe' in current_df.columns:
        system_vulns = current_df['affected_cpe'].apply(
            lambda x: str(x).split(':')[1] if ':' in str(x) else str(x)
        ).value_counts().head(10)
        
        system_fig = px.bar(
            x=system_vulns.values,
            y=system_vulns.index,
            orientation='h',
            title="Top 10 Vulnerable Systems",
            color=system_vulns.values,
            color_continuous_scale='Reds'
        )
        system_fig.update_layout(height=350, xaxis_title="Vulnerability Count", yaxis_title="System")
    else:
        system_fig = go.Figure()
        system_fig.update_layout(
            title="System Data Not Available",
            height=350
        )
    
    return pyramid_fig, cvss_fig, exploit_fig, scatter_fig, system_fig

if __name__ == '__main__':
    print("\n" + "="*60)
    print("VulnCheck Vulnerability Dashboard")
    print("="*60)
    print(f"📊 Loaded {len(df)} vulnerabilities")
    print(f"🔴 Critical: {stats['critical_severity']}")
    print(f"🟠 High: {stats['high_severity']}")
    print(f"💥 With Exploits: {stats['with_exploits']}")
    print(f"🎯 CISA KEV: {stats['cisa_kev']}")
    print("\n🌐 Dashboard running at: http://localhost:8050")
    print("Press Ctrl+C to stop")
    print("="*60 + "\n")
    
    # Run without debug/reloader and disable Dash dev tools hot reload
    # to prevent client-side polling (/_reload-hash) which can cause
    # automatic browser refreshes or scrolling.
    app.run(debug=False, port=8050, use_reloader=False,
            dev_tools_hot_reload=False, dev_tools_props_check=False, dev_tools_ui=False)