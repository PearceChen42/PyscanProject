#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
扫描结果 Web 仪表板
使用: python web_dashboard.py
"""

import os
import sqlite3
import glob
from datetime import datetime
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

def get_all_scan_sessions():
    """获取所有扫描会话"""
    scan_sessions = []
    scan_dirs = glob.glob("scans/*")
   
    for scan_dir in scan_dirs:
        db_path = os.path.join(scan_dir, "scan_results.db")
        if os.path.exists(db_path):
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
               
                cursor.execute("SELECT id, domain, start_time, end_time, status, subdomain_count, alive_domain_count, vulnerability_count FROM scan_sessions")
                session_data = cursor.fetchone()
               
                if session_data:
                    session_info = {
                        "id": session_data[0],
                        "domain": session_data[1],
                        "start_time": session_data[2],
                        "end_time": session_data[3],
                        "status": session_data[4],
                        "subdomain_count": session_data[5],
                        "alive_domain_count": session_data[6],
                        "vulnerability_count": session_data[7],
                        "db_path": db_path,
                        "scan_dir": scan_dir
                    }
                    scan_sessions.append(session_info)
               
                conn.close()
            except sqlite3.Error as e:
                print(f"数据库错误: {e}")
   
    # 按开始时间倒序排列
    scan_sessions.sort(key=lambda x: x["start_time"], reverse=True)
    return scan_sessions

def get_scan_session(db_path, session_id):
    """获取特定扫描会话的详细信息"""
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
       
        # 获取会话基本信息
        cursor.execute(
            "SELECT id, domain, start_time, end_time, status, subdomain_count, alive_domain_count, vulnerability_count FROM scan_sessions WHERE id = ?",
            (session_id,)
        )
        session_data = cursor.fetchone()
       
        if not session_data:
            return None
       
        session_info = dict(session_data)
       
        # 获取子域名列表
        cursor.execute(
            "SELECT id, subdomain, discovered_at FROM subdomains WHERE scan_session_id = ? ORDER BY subdomain",
            (session_id,)
        )
        session_info["subdomains"] = [dict(row) for row in cursor.fetchall()]
       
        # 获取存活域名列表
        cursor.execute(
            """SELECT id, url, status_code, title, content_length, technology, discovered_at
               FROM alive_domains WHERE scan_session_id = ? ORDER BY url""",
            (session_id,)
        )
        session_info["alive_domains"] = [dict(row) for row in cursor.fetchall()]
       
        # 获取漏洞列表
        cursor.execute(
            """SELECT v.id, v.template_id, v.template_name, v.template_url, v.host, v.matched_at,
                      v.severity, v.description, v.reference, v.timestamp, a.url as target_url
               FROM vulnerabilities v
               JOIN alive_domains a ON v.alive_domain_id = a.id
               WHERE v.scan_session_id = ?
               ORDER BY v.severity DESC, v.timestamp DESC""",
            (session_id,)
        )
        session_info["vulnerabilities"] = [dict(row) for row in cursor.fetchall()]
       
        # 按严重性统计漏洞
        cursor.execute(
            "SELECT severity, COUNT(*) as count FROM vulnerabilities WHERE scan_session_id = ? GROUP BY severity",
            (session_id,)
        )
        severity_stats = {}
        for row in cursor.fetchall():
            severity_stats[row[0]] = row[1]
        session_info["severity_stats"] = severity_stats
       
        conn.close()
        return session_info
       
    except sqlite3.Error as e:
        print(f"数据库错误: {e}")
        return None

@app.route('/')
def index():
    """主页 - 显示所有扫描会话"""
    scan_sessions = get_all_scan_sessions()
    return render_template('index.html', sessions=scan_sessions)

@app.route('/session/<session_id>')
def session_detail(session_id):
    """扫描会话详情页"""
    # 查找包含该会话的数据库
    scan_sessions = get_all_scan_sessions()
    target_session = None
    db_path = None
   
    for session in scan_sessions:
        if str(session["id"]) == session_id:
            target_session = session
            db_path = session["db_path"]
            break
   
    if not target_session:
        return "扫描会话未找到", 404
   
    # 获取会话详细信息
    session_info = get_scan_session(db_path, session_id)
    if not session_info:
        return "扫描会话数据加载失败", 500
   
    return render_template('session_detail.html', session=session_info)

@app.route('/api/sessions')
def api_sessions():
    """API: 获取所有扫描会话"""
    scan_sessions = get_all_scan_sessions()
    return jsonify(scan_sessions)

@app.route('/api/session/<session_id>')
def api_session_detail(session_id):
    """API: 获取特定扫描会话的详细信息"""
    # 查找包含该会话的数据库
    scan_sessions = get_all_scan_sessions()
    db_path = None
   
    for session in scan_sessions:
        if str(session["id"]) == session_id:
            db_path = session["db_path"]
            break
   
    if not db_path:
        return jsonify({"error": "扫描会话未找到"}), 404
   
    # 获取会话详细信息
    session_info = get_scan_session(db_path, session_id)
    if not session_info:
        return jsonify({"error": "扫描会话数据加载失败"}), 500
   
    return jsonify(session_info)

@app.route('/api/vulnerabilities/<session_id>')
def api_vulnerabilities(session_id):
    """API: 获取特定扫描会话的漏洞信息"""
    # 查找包含该会话的数据库
    scan_sessions = get_all_scan_sessions()
    db_path = None
   
    for session in scan_sessions:
        if str(session["id"]) == session_id:
            db_path = session["db_path"]
            break
   
    if not db_path:
        return jsonify({"error": "扫描会话未找到"}), 404
   
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
       
        # 获取漏洞列表
        cursor.execute(
            """SELECT v.id, v.template_id, v.template_name, v.template_url, v.host, v.matched_at,
                      v.severity, v.description, v.reference, v.timestamp, a.url as target_url
               FROM vulnerabilities v
               JOIN alive_domains a ON v.alive_domain_id = a.id
               WHERE v.scan_session_id = ?
               ORDER BY v.severity DESC, v.timestamp DESC""",
            (session_id,)
        )
        vulnerabilities = [dict(row) for row in cursor.fetchall()]
       
        conn.close()
        return jsonify(vulnerabilities)
       
    except sqlite3.Error as e:
        return jsonify({"error": f"数据库错误: {e}"}), 500

if __name__ == '__main__':
    # 创建模板目录
    os.makedirs("templates", exist_ok=True)
   
    # 创建首页模板
    if not os.path.exists("templates/index.html"):
        with open("templates/index.html", "w") as f:
            f.write('''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>安全扫描仪表板</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .severity-critical { color: #dc3545; }
        .severity-high { color: #fd7e14; }
        .severity-medium { color: #ffc107; }
        .severity-low { color: #20c997; }
        .severity-info { color: #0dcaf0; }
        .card { margin-bottom: 20px; }
        .stat-card { text-align: center; }
        .stat-number { font-size: 2rem; font-weight: bold; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/">
                <i class="fas fa-shield-alt"></i> 安全扫描仪表板
            </a>
        </div>
    </nav>

    <div class="container mt-4">
        <h1>扫描会话列表</h1>
       
        {% if sessions %}
            <div class="row">
                {% for session in sessions %}
                    <div class="col-md-6 col-lg-4">
                        <div class="card">
                            <div class="card-body">
                                <h5 class="card-title">{{ session.domain }}</h5>
                                <h6 class="card-subtitle mb-2 text-muted">
                                    扫描时间: {{ session.start_time }}
                                </h6>
                                <p class="card-text">
                                    <span class="badge bg-{{ 'success' if session.status == 'completed' else 'warning' }}">
                                        {{ session.status }}
                                    </span>
                                </p>
                                <div class="d-flex justify-content-between">
                                    <div>
                                        <small class="text-muted">子域名: {{ session.subdomain_count }}</small>
                                    </div>
                                    <div>
                                        <small class="text-muted">存活: {{ session.alive_domain_count }}</small>
                                    </div>
                                    <div>
                                        <small class="text-muted">漏洞: {{ session.vulnerability_count }}</small>
                                    </div>
                                </div>
                                <a href="/session/{{ session.id }}" class="btn btn-primary btn-sm mt-2">
                                    查看详情
                                </a>
                            </div>
                        </div>
                    </div>
                {% endfor %}
            </div>
        {% else %}
            <div class="alert alert-info">
                没有找到扫描会话。请先运行扫描脚本。
            </div>
        {% endif %}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>''')
   
    # 创建会话详情模板
    if not os.path.exists("templates/session_detail.html"):
        with open("templates/session_detail.html", "w") as f:
            f.write('''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ session.domain }} - 扫描详情</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .severity-critical { color: #dc3545; }
        .severity-high { color: #fd7e14; }
        .severity-medium { color: #ffc107; }
        .severity-low { color: #20c997; }
        .severity-info { color: #0dcaf0; }
        .card { margin-bottom: 20px; }
        .stat-card { text-align: center; }
        .stat-number { font-size: 2rem; font-weight: bold; }
        .nav-tabs .nav-link.active { font-weight: bold; }
        .vuln-card { border-left: 4px solid; margin-bottom: 15px; }
        .vuln-card.critical { border-left-color: #dc3545; }
        .vuln-card.high { border-left-color: #fd7e14; }
        .vuln-card.medium { border-left-color: #ffc107; }
        .vuln-card.low { border-left-color: #20c997; }
        .vuln-card.info { border-left-color: #0dcaf0; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/">
                <i class="fas fa-shield-alt"></i> 安全扫描仪表板
            </a>
        </div>
    </nav>

    <div class="container mt-4">
        <div class="d-flex justify-content-between align-items-center">
            <h1>{{ session.domain }} 扫描详情</h1>
            <a href="/" class="btn btn-outline-secondary">
                <i class="fas fa-arrow-left"></i> 返回列表
            </a>
        </div>
       
        <p class="text-muted">
            扫描时间: {{ session.start_time }} - {{ session.end_time or "进行中" }}
        </p>
       
        <!-- 统计卡片 -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card stat-card">
                    <div class="card-body">
                        <div class="stat-number">{{ session.subdomain_count }}</div>
                        <div>子域名</div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card">
                    <div class="card-body">
                        <div class="stat-number">{{ session.alive_domain_count }}</div>
                        <div>存活域名</div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card">
                    <div class="card-body">
                        <div class="stat-number">{{ session.vulnerability_count }}</div>
                        <div>发现漏洞</div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card">
                    <div class="card-body">
                        <div class="stat-number">
                            {% if session.severity_stats.critical %}
                                <span class="severity-critical">{{ session.severity_stats.critical }}</span>
                            {% else %}0{% endif %}
                        </div>
                        <div>严重漏洞</div>
                    </div>
                </div>
            </div>
        </div>
       
        <!-- 选项卡导航 -->
        <ul class="nav nav-tabs" id="myTab" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" id="vulnerabilities-tab" data-bs-toggle="tab" data-bs-target="#vulnerabilities" type="button" role="tab">
                    漏洞 ({{ session.vulnerability_count }})
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="domains-tab" data-bs-toggle="tab" data-bs-target="#domains" type="button" role="tab">
                    存活域名 ({{ session.alive_domain_count }})
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="subdomains-tab" data-bs-toggle="tab" data-bs-target="#subdomains" type="button" role="tab">
                    子域名 ({{ session.subdomain_count }})
                </button>
            </li>
        </ul>
       
        <!-- 选项卡内容 -->
        <div class="tab-content" id="myTabContent">
            <!-- 漏洞选项卡 -->
            <div class="tab-pane fade show active" id="vulnerabilities" role="tabpanel">
                {% if session.vulnerabilities %}
                    {% for vuln in session.vulnerabilities %}
                        <div class="card vuln-card {{ vuln.severity.lower() }}">
                            <div class="card-body">
                                <div class="d-flex justify-content-between align-items-start">
                                    <h5 class="card-title">
                                        <span class="severity-{{ vuln.severity.lower() }}">
                                            {{ vuln.severity.upper() }}
                                        </span>: {{ vuln.template_name }}
                                    </h5>
                                    <span class="badge bg-secondary">{{ vuln.timestamp }}</span>
                                </div>
                                <h6 class="card-subtitle mb-2 text-muted">
                                    <i class="fas fa-globe"></i> {{ vuln.target_url }}
                                </h6>
                                <p class="card-text">{{ vuln.description }}</p>
                                {% if vuln.reference %}
                                    <p class="card-text">
                                        <small class="text-muted">
                                            参考: {{ vuln.reference }}
                                        </small>
                                    </p>
                                {% endif %}
                                <div class="d-flex justify-content-between align-items-center">
                                    <small class="text-muted">
                                        模板ID: {{ vuln.template_id }}
                                    </small>
                                    <a href="{{ vuln.target_url }}" target="_blank" class="btn btn-sm btn-outline-primary">
                                        访问目标 <i class="fas fa-external-link-alt"></i>
                                    </a>
                                </div>
                            </div>
                        </div>
                    {% endfor %}
                {% else %}
                    <div class="alert alert-info mt-3">
                        未发现漏洞。
                    </div>
                {% endif %}
            </div>
           
            <!-- 存活域名选项卡 -->
            <div class="tab-pane fade" id="domains" role="tabpanel">
                {% if session.alive_domains %}
                    <div class="table-responsive mt-3">
                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <th>URL</th>
                                    <th>状态码</th>
                                    <th>标题</th>
                                    <th>技术</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for domain in session.alive_domains %}
                                    <tr>
                                        <td>
                                            <a href="{{ domain.url }}" target="_blank">
                                                {{ domain.url }}
                                            </a>
                                        </td>
                                        <td>
                                            <span class="badge bg-{{ 'success' if domain.status_code == 200 else 'warning' }}">
                                                {{ domain.status_code }}
                                            </span>
                                        </td>
                                        <td>{{ domain.title or 'N/A' }}</td>
                                        <td>{{ domain.technology or 'N/A' }}</td>
                                    </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                {% else %}
                    <div class="alert alert-info mt-3">
                        未发现存活的域名。
                    </div>
                {% endif %}
            </div>
           
            <!-- 子域名选项卡 -->
            <div class="tab-pane fade" id="subdomains" role="tabpanel">
                {% if session.subdomains %}
                    <div class="table-responsive mt-3">
                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <th>子域名</th>
                                    <th>发现时间</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for subdomain in session.subdomains %}
                                    <tr>
                                        <td>{{ subdomain.subdomain }}</td>
                                        <td>{{ subdomain.discovered_at }}</td>
                                    </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                {% else %}
                    <div class="alert alert-info mt-3">
                        未发现子域名。
                    </div>
                {% endif %}
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>''')

    # 启动 Flask 应用
    app.run(debug=True, host='0.0.0.0', port=5000)