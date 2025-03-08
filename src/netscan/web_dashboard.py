#!/usr/bin/env python3

import os
import json
import time
import threading
import webbrowser
import socket
import traceback
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash

from .network_discovery import get_network_info, discover_devices

class WebDashboard:
    """Web dashboard interface for the network scanner using Flask"""
    
    def __init__(self, display, identifier, port=5000):
        """Initialize the web dashboard"""
        self.display = display
        self.identifier = identifier
        self.requested_port = port
        self.port = self._find_available_port(port)
        self.app = Flask(__name__, template_folder=self._get_template_dir())
        
        # Configure Flask app
        self.app.secret_key = os.urandom(24)  # Required for flash messages
        self.app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0  # Disable caching for development
        
        # App state
        self.network_info = None
        self.devices = []
        self.scanning = False
        self.port_scanning = {}  # Track port scanning by IP
        self.last_scan_time = None
        
        # Register routes
        self._register_routes()
        
    def _find_available_port(self, start_port):
        """Find an available port starting from start_port and incrementing until one is found"""
        current_port = start_port
        max_port = 65535  # Maximum port number
        
        while current_port <= max_port:
            try:
                # Try to open a socket on the port
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.bind(('127.0.0.1', current_port))
                sock.close()
                # If we get here, the port is available
                return current_port
            except socket.error:
                # Port is in use, try the next one
                current_port += 1
        
        # If we get here, no ports are available
        raise Exception("No available ports found")
    
    def _get_template_dir(self):
        """Get or create the templates directory"""
        # Create templates directory in the same directory as this file
        template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
        os.makedirs(template_dir, exist_ok=True)
        
        # Create the HTML templates
        self._create_templates(template_dir)
        
        return template_dir
    
    def _create_templates(self, template_dir):
        """Create HTML templates for the web dashboard"""
        # Base template
        base_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}NetScan Dashboard{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        body {
            padding-top: 56px;
        }
        .navbar-brand {
            font-weight: bold;
        }
        .card {
            margin-bottom: 1rem;
        }
        .status-healthy {
            color: #198754;
        }
        .status-unhealthy {
            color: #dc3545;
        }
        .status-unknown {
            color: #6c757d;
        }
        .gateway-badge {
            margin-left: 5px;
        }
    </style>
    {% block extra_head %}{% endblock %}
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark fixed-top">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">NetScan Dashboard</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav">
                    <li class="nav-item">
                        <a class="nav-link" href="/">Home</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/devices">Devices</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/labels">Labels</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        {% block content %}{% endblock %}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    {% block scripts %}{% endblock %}
</body>
</html>"""

        # Index template
        index_html = """{% extends "base.html" %}

{% block title %}NetScan Dashboard{% endblock %}

{% block content %}
<div class="row">
    <div class="col-md-12">
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="mb-0">Network Information</h5>
                {% if network_info %}
                <span class="badge bg-success">Connected</span>
                {% else %}
                <span class="badge bg-secondary">Not Connected</span>
                {% endif %}
            </div>
            <div class="card-body">
                {% if network_info %}
                <div class="row">
                    <div class="col-md-4">
                        <p><strong>Network:</strong> {{ network_info.network_cidr }}</p>
                    </div>
                    <div class="col-md-4">
                        <p><strong>Interface:</strong> {{ network_info.interface }}</p>
                    </div>
                    <div class="col-md-4">
                        <p><strong>Local IP:</strong> {{ network_info.ip }}</p>
                    </div>
                </div>
                {% else %}
                <p class="text-muted">Network information not available. Run a scan to connect.</p>
                {% endif %}
            </div>
        </div>
    </div>
</div>

<div class="row mt-3">
    <div class="col-md-12">
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">Network Scan</h5>
            </div>
            <div class="card-body">
                <form id="scan-form" action="/scan" method="post" class="mb-3">
                    <div class="row g-3 align-items-center">
                        <div class="col-auto">
                            <label for="network_cidr" class="col-form-label">Network Range:</label>
                        </div>
                        <div class="col-md-4">
                            <input type="text" id="network_cidr" name="network_cidr" class="form-control" 
                                   value="{{ network_info.network_cidr if network_info else '192.168.1.0/24' }}">
                        </div>
                        <div class="col-auto">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="health_check" name="health_check" checked>
                                <label class="form-check-label" for="health_check">
                                    Health Check
                                </label>
                            </div>
                        </div>
                        <div class="col-auto">
                            <button type="submit" id="scan-button" class="btn btn-primary">
                                <i class="bi bi-search me-2"></i>Scan Network
                            </button>
                        </div>
                    </div>
                </form>
                
                <div id="scan-status">
                    {% if scanning %}
                    <div class="alert alert-info">
                        <div class="spinner-border spinner-border-sm me-2" role="status"></div>
                        <span>Scanning in progress...</span>
                    </div>
                    {% elif devices %}
                    <div class="alert alert-success">
                        <i class="bi bi-check-circle me-2"></i>
                        <span>Last scan completed {{ last_scan_time }} - {{ devices|length }} devices found</span>
                    </div>
                    {% endif %}
                </div>
            </div>
        </div>
    </div>
</div>

<div class="row mt-3">
    <div class="col-md-12">
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="mb-0">Recent Scan Results</h5>
                {% if devices %}
                <a href="/devices" class="btn btn-sm btn-outline-primary">View All Devices</a>
                {% endif %}
            </div>
            <div class="card-body">
                {% if devices %}
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>MAC Address</th>
                                <th>Hostname</th>
                                <th>Device Type</th>
                                <th>Status</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for device in devices[:5] %}
                            <tr>
                                <td>{{ device.ip }}</td>
                                <td>{{ device.mac }}</td>
                                <td>{{ device.hostname|default('Unknown', true) }}</td>
                                <td>{{ device.device_type|default('Unknown', true) }}</td>
                                <td>
                                    {% if device.health == 'healthy' %}
                                    <span class="status-healthy"><i class="bi bi-check-circle"></i> Healthy</span>
                                    {% elif device.health == 'unhealthy' %}
                                    <span class="status-unhealthy"><i class="bi bi-exclamation-triangle"></i> Unhealthy</span>
                                    {% else %}
                                    <span class="status-unknown"><i class="bi bi-question-circle"></i> Unknown</span>
                                    {% endif %}
                                    
                                    {% if device.is_gateway %}
                                    <span class="badge bg-info gateway-badge">Gateway</span>
                                    {% endif %}
                                </td>
                                <td>
                                    <a href="/device/{{ device.ip }}" class="btn btn-sm btn-outline-primary">
                                        <i class="bi bi-info-circle"></i>
                                    </a>
                                    <a href="/port-scan/{{ device.ip }}" class="btn btn-sm btn-outline-secondary">
                                        <i class="bi bi-hdd-network"></i>
                                    </a>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% if devices|length > 5 %}
                <div class="text-center mt-3">
                    <a href="/devices" class="btn btn-outline-primary">View All {{ devices|length }} Devices</a>
                </div>
                {% endif %}
                {% else %}
                <p class="text-muted">No devices have been discovered yet. Run a scan to discover devices.</p>
                {% endif %}
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
    $(document).ready(function() {
        $('#scan-form').submit(function(e) {
            e.preventDefault();
            
            // Update UI to show scanning
            $('#scan-status').html(`
                <div class="alert alert-info">
                    <div class="spinner-border spinner-border-sm me-2" role="status"></div>
                    <span>Scanning in progress...</span>
                </div>
            `);
            
            // Disable button
            $('#scan-button').prop('disabled', true);
            
            // Submit the form via AJAX
            $.ajax({
                type: 'POST',
                url: '/scan',
                data: $(this).serialize(),
                success: function(response) {
                    if (response.success) {
                        // Poll for scan completion
                        pollScanStatus();
                    } else {
                        $('#scan-status').html(`
                            <div class="alert alert-danger">
                                <i class="bi bi-exclamation-triangle me-2"></i>
                                <span>Error: ${response.message}</span>
                            </div>
                        `);
                        $('#scan-button').prop('disabled', false);
                    }
                },
                error: function() {
                    $('#scan-status').html(`
                        <div class="alert alert-danger">
                            <i class="bi bi-exclamation-triangle me-2"></i>
                            <span>An error occurred while starting the scan.</span>
                        </div>
                    `);
                    $('#scan-button').prop('disabled', false);
                }
            });
        });
        
        function pollScanStatus() {
            $.ajax({
                url: '/scan-status',
                success: function(response) {
                    if (response.scanning) {
                        // Still scanning, poll again in 2 seconds
                        setTimeout(pollScanStatus, 2000);
                    } else {
                        // Scan complete, reload page
                        window.location.reload();
                    }
                },
                error: function() {
                    // Error occurred, stop polling
                    $('#scan-status').html(`
                        <div class="alert alert-danger">
                            <i class="bi bi-exclamation-triangle me-2"></i>
                            <span>An error occurred while checking scan status.</span>
                        </div>
                    `);
                    $('#scan-button').prop('disabled', false);
                }
            });
        }
    });
</script>
{% endblock %}"""

        # Devices template
        devices_html = """{% extends "base.html" %}

{% block title %}Network Devices - NetScan Dashboard{% endblock %}

{% block content %}
<div class="row">
    <div class="col-md-12">
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="mb-0">Network Devices</h5>
                <a href="/" class="btn btn-sm btn-outline-primary">Back to Dashboard</a>
            </div>
            <div class="card-body">
                {% if devices %}
                <div class="mb-3">
                    <input type="text" class="form-control" id="deviceSearch" placeholder="Search devices...">
                </div>
                
                <div class="table-responsive">
                    <table class="table table-hover" id="deviceTable">
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>MAC Address</th>
                                <th>Hostname</th>
                                <th>Device Type</th>
                                <th>Vendor</th>
                                <th>Status</th>
                                <th>Label</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for device in devices %}
                            <tr>
                                <td>{{ device.ip }}</td>
                                <td>{{ device.mac }}</td>
                                <td>{{ device.hostname|default('Unknown', true) }}</td>
                                <td>{{ device.device_type|default('Unknown', true) }}</td>
                                <td>{{ device.vendor|default('Unknown', true) }}</td>
                                <td>
                                    {% if device.health == 'healthy' %}
                                    <span class="status-healthy"><i class="bi bi-check-circle"></i> Healthy</span>
                                    {% elif device.health == 'unhealthy' %}
                                    <span class="status-unhealthy"><i class="bi bi-exclamation-triangle"></i> Unhealthy</span>
                                    {% else %}
                                    <span class="status-unknown"><i class="bi bi-question-circle"></i> Unknown</span>
                                    {% endif %}
                                    
                                    {% if device.is_gateway %}
                                    <span class="badge bg-info gateway-badge">Gateway</span>
                                    {% endif %}
                                </td>
                                <td>
                                    {% if device.label %}
                                    {{ device.label }}
                                    {% else %}
                                    <span class="text-muted">No label</span>
                                    {% endif %}
                                </td>
                                <td>
                                    <a href="/device/{{ device.ip }}" class="btn btn-sm btn-outline-primary">
                                        <i class="bi bi-info-circle"></i>
                                    </a>
                                    <a href="/port-scan/{{ device.ip }}" class="btn btn-sm btn-outline-secondary">
                                        <i class="bi bi-hdd-network"></i>
                                    </a>
                                    <button class="btn btn-sm btn-outline-success" 
                                           data-bs-toggle="modal" 
                                           data-bs-target="#labelModal" 
                                           data-ip="{{ device.ip }}"
                                           data-current-label="{{ device.label|default('', true) }}">
                                        <i class="bi bi-tag"></i>
                                    </button>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                
                <!-- Label Modal -->
                <div class="modal fade" id="labelModal" tabindex="-1" aria-hidden="true">
                    <div class="modal-dialog">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title">Device Label</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                            </div>
                            <div class="modal-body">
                                <form id="labelForm" action="/update-label" method="post">
                                    <input type="hidden" id="deviceIp" name="ip">
                                    <div class="mb-3">
                                        <label for="deviceLabel" class="form-label">Label</label>
                                        <input type="text" class="form-control" id="deviceLabel" name="label">
                                    </div>
                                </form>
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                <button type="button" class="btn btn-danger" id="removeLabel">Remove Label</button>
                                <button type="button" class="btn btn-primary" id="saveLabel">Save Label</button>
                            </div>
                        </div>
                    </div>
                </div>
                {% else %}
                <p class="text-muted">No devices have been discovered yet. Run a scan to discover devices.</p>
                <a href="/" class="btn btn-primary">Go to Dashboard</a>
                {% endif %}
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
    $(document).ready(function() {
        // Device search functionality
        $("#deviceSearch").on("keyup", function() {
            var value = $(this).val().toLowerCase();
            $("#deviceTable tbody tr").filter(function() {
                $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
            });
        });
        
        // Label modal
        $('#labelModal').on('show.bs.modal', function (event) {
            var button = $(event.relatedTarget);
            var ip = button.data('ip');
            var currentLabel = button.data('current-label');
            
            var modal = $(this);
            modal.find('#deviceIp').val(ip);
            modal.find('#deviceLabel').val(currentLabel);
        });
        
        // Save label
        $('#saveLabel').click(function() {
            $.ajax({
                type: 'POST',
                url: '/update-label',
                data: $('#labelForm').serialize(),
                success: function(response) {
                    if (response.success) {
                        $('#labelModal').modal('hide');
                        window.location.reload();
                    } else {
                        alert('Error updating label: ' + response.message);
                    }
                },
                error: function() {
                    alert('An error occurred while updating the label.');
                }
            });
        });
        
        // Remove label
        $('#removeLabel').click(function() {
            var ip = $('#deviceIp').val();
            $.ajax({
                type: 'POST',
                url: '/remove-label',
                data: { ip: ip },
                success: function(response) {
                    if (response.success) {
                        $('#labelModal').modal('hide');
                        window.location.reload();
                    } else {
                        alert('Error removing label: ' + response.message);
                    }
                },
                error: function() {
                    alert('An error occurred while removing the label.');
                }
            });
        });
    });
</script>
{% endblock %}"""

        # Device detail template
        device_detail_html = """{% extends "base.html" %}

{% block title %}Device Details - NetScan Dashboard{% endblock %}

{% block content %}
<div class="row">
    <div class="col-md-12">
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="mb-0">Device Details: {{ device.ip }}</h5>
                <div>
                    <a href="/port-scan/{{ device.ip }}" class="btn btn-sm btn-outline-secondary me-2">
                        <i class="bi bi-hdd-network me-1"></i> Port Scan
                    </a>
                    <a href="/devices" class="btn btn-sm btn-outline-primary">Back to Devices</a>
                </div>
            </div>
            <div class="card-body">
                {% if device %}
                <div class="row">
                    <div class="col-md-6">
                        <div class="card mb-3">
                            <div class="card-header">Basic Information</div>
                            <div class="card-body">
                                <table class="table table-striped">
                                    <tbody>
                                        <tr>
                                            <th>IP Address</th>
                                            <td>{{ device.ip }}</td>
                                        </tr>
                                        <tr>
                                            <th>MAC Address</th>
                                            <td>{{ device.mac }}</td>
                                        </tr>
                                        <tr>
                                            <th>Hostname</th>
                                            <td>{{ device.hostname|default('Unknown', true) }}</td>
                                        </tr>
                                        <tr>
                                            <th>Device Type</th>
                                            <td>{{ device.device_type|default('Unknown', true) }}</td>
                                        </tr>
                                        <tr>
                                            <th>Vendor</th>
                                            <td>{{ device.vendor|default('Unknown', true) }}</td>
                                        </tr>
                                        <tr>
                                            <th>Status</th>
                                            <td>
                                                {% if device.health == 'healthy' %}
                                                <span class="status-healthy"><i class="bi bi-check-circle"></i> Healthy</span>
                                                {% elif device.health == 'unhealthy' %}
                                                <span class="status-unhealthy"><i class="bi bi-exclamation-triangle"></i> Unhealthy</span>
                                                {% else %}
                                                <span class="status-unknown"><i class="bi bi-question-circle"></i> Unknown</span>
                                                {% endif %}
                                            </td>
                                        </tr>
                                        <tr>
                                            <th>Gateway</th>
                                            <td>
                                                {% if device.is_gateway %}
                                                <span class="text-primary"><i class="bi bi-check-lg"></i> Yes</span>
                                                {% else %}
                                                <span class="text-secondary">No</span>
                                                {% endif %}
                                            </td>
                                        </tr>
                                        <tr>
                                            <th>Label</th>
                                            <td>
                                                <div class="d-flex align-items-center">
                                                    {% if device.label %}
                                                    <span>{{ device.label }}</span>
                                                    {% else %}
                                                    <span class="text-muted">No label</span>
                                                    {% endif %}
                                                    <button class="btn btn-sm btn-outline-primary ms-2" 
                                                           data-bs-toggle="modal" 
                                                           data-bs-target="#labelModal"
                                                           data-ip="{{ device.ip }}"
                                                           data-current-label="{{ device.label|default('', true) }}">
                                                        <i class="bi bi-pencil"></i>
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-6">
                        {% if device.ports %}
                        <div class="card mb-3">
                            <div class="card-header d-flex justify-content-between align-items-center">
                                <span>Open Ports</span>
                                <a href="/port-scan/{{ device.ip }}" class="btn btn-sm btn-outline-primary">
                                    <i class="bi bi-arrow-repeat me-1"></i> Rescan
                                </a>
                            </div>
                            <div class="card-body">
                                <table class="table table-striped">
                                    <thead>
                                        <tr>
                                            <th>Port</th>
                                            <th>Service</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {% for port, service in device.ports.items() %}
                                        <tr>
                                            <td>{{ port }}</td>
                                            <td>{{ service }}</td>
                                        </tr>
                                        {% endfor %}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                        {% else %}
                        <div class="card mb-3">
                            <div class="card-header">Open Ports</div>
                            <div class="card-body">
                                <p class="text-muted">No port scan information available.</p>
                                <a href="/port-scan/{{ device.ip }}" class="btn btn-primary">
                                    <i class="bi bi-hdd-network me-1"></i> Scan Ports
                                </a>
                            </div>
                        </div>
                        {% endif %}
                        
                        <div class="card">
                            <div class="card-header">Actions</div>
                            <div class="card-body">
                                <div class="d-grid gap-2">
                                    <a href="http://{{ device.ip }}" target="_blank" class="btn btn-outline-primary">
                                        <i class="bi bi-box-arrow-up-right me-1"></i> Open Web Interface
                                    </a>
                                    <a href="/ping/{{ device.ip }}" class="btn btn-outline-secondary">
                                        <i class="bi bi-activity me-1"></i> Ping Device
                                    </a>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Label Modal -->
                <div class="modal fade" id="labelModal" tabindex="-1" aria-hidden="true">
                    <div class="modal-dialog">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title">Device Label</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                            </div>
                            <div class="modal-body">
                                <form id="labelForm" action="/update-label" method="post">
                                    <input type="hidden" id="deviceIp" name="ip">
                                    <div class="mb-3">
                                        <label for="deviceLabel" class="form-label">Label</label>
                                        <input type="text" class="form-control" id="deviceLabel" name="label">
                                    </div>
                                </form>
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                <button type="button" class="btn btn-danger" id="removeLabel">Remove Label</button>
                                <button type="button" class="btn btn-primary" id="saveLabel">Save Label</button>
                            </div>
                        </div>
                    </div>
                </div>
                {% else %}
                <div class="alert alert-warning">
                    <i class="bi bi-exclamation-triangle me-2"></i>
                    Device not found.
                </div>
                <a href="/devices" class="btn btn-primary">Back to Devices</a>
                {% endif %}
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
    $(document).ready(function() {
        // Label modal
        $('#labelModal').on('show.bs.modal', function (event) {
            var button = $(event.relatedTarget);
            var ip = button.data('ip');
            var currentLabel = button.data('current-label');
            
            var modal = $(this);
            modal.find('#deviceIp').val(ip);
            modal.find('#deviceLabel').val(currentLabel);
        });
        
        // Save label
        $('#saveLabel').click(function() {
            $.ajax({
                type: 'POST',
                url: '/update-label',
                data: $('#labelForm').serialize(),
                success: function(response) {
                    if (response.success) {
                        $('#labelModal').modal('hide');
                        window.location.reload();
                    } else {
                        alert('Error updating label: ' + response.message);
                    }
                },
                error: function() {
                    alert('An error occurred while updating the label.');
                }
            });
        });
        
        // Remove label
        $('#removeLabel').click(function() {
            var ip = $('#deviceIp').val();
            $.ajax({
                type: 'POST',
                url: '/remove-label',
                data: { ip: ip },
                success: function(response) {
                    if (response.success) {
                        $('#labelModal').modal('hide');
                        window.location.reload();
                    } else {
                        alert('Error removing label: ' + response.message);
                    }
                },
                error: function() {
                    alert('An error occurred while removing the label.');
                }
            });
        });
    });
</script>
{% endblock %}"""

        # Labels template
        labels_html = """{% extends "base.html" %}

{% block title %}Device Labels - NetScan Dashboard{% endblock %}

{% block content %}
<div class="row">
    <div class="col-md-12">
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="mb-0">Device Labels</h5>
                <button class="btn btn-sm btn-primary" data-bs-toggle="modal" data-bs-target="#addLabelModal">
                    <i class="bi bi-plus-lg me-1"></i> Add Label
                </button>
            </div>
            <div class="card-body">
                {% if labels %}
                <div class="mb-3">
                    <input type="text" class="form-control" id="labelSearch" placeholder="Search labels...">
                </div>
                
                <div class="table-responsive">
                    <table class="table table-hover" id="labelTable">
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>Label</th>
                                <th>Device Info</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for ip, label in labels.items() %}
                            <tr>
                                <td>{{ ip }}</td>
                                <td>{{ label }}</td>
                                <td>
                                    {% set found = false %}
                                    {% for device in devices %}
                                        {% if device.ip == ip %}
                                            {% set found = true %}
                                            {{ device.hostname|default('Unknown', true) }}
                                            ({{ device.device_type|default('Unknown', true) }})
                                        {% endif %}
                                    {% endfor %}
                                    
                                    {% if not found %}
                                    <span class="text-muted">Device not in current scan</span>
                                    {% endif %}
                                </td>
                                <td>
                                    <button class="btn btn-sm btn-outline-primary" 
                                           data-bs-toggle="modal" 
                                           data-bs-target="#editLabelModal" 
                                           data-ip="{{ ip }}"
                                           data-label="{{ label }}">
                                        <i class="bi bi-pencil"></i>
                                    </button>
                                    <button class="btn btn-sm btn-outline-danger delete-label" data-ip="{{ ip }}">
                                        <i class="bi bi-trash"></i>
                                    </button>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% else %}
                <p class="text-muted">No device labels found. Add labels to help identify your network devices.</p>
                {% endif %}
            </div>
        </div>
    </div>
</div>

<!-- Add Label Modal -->
<div class="modal fade" id="addLabelModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Add Device Label</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <form id="addLabelForm" action="/update-label" method="post">
                    <div class="mb-3">
                        <label for="newDeviceIp" class="form-label">IP Address</label>
                        <input type="text" class="form-control" id="newDeviceIp" name="ip" required>
                    </div>
                    <div class="mb-3">
                        <label for="newDeviceLabel" class="form-label">Label</label>
                        <input type="text" class="form-control" id="newDeviceLabel" name="label" required>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-primary" id="addLabel">Add Label</button>
            </div>
        </div>
    </div>
</div>

<!-- Edit Label Modal -->
<div class="modal fade" id="editLabelModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Edit Device Label</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <form id="editLabelForm" action="/update-label" method="post">
                    <input type="hidden" id="editDeviceIp" name="ip">
                    <div class="mb-3">
                        <label for="editDeviceLabel" class="form-label">Label</label>
                        <input type="text" class="form-control" id="editDeviceLabel" name="label" required>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-primary" id="updateLabel">Update Label</button>
            </div>
        </div>
    </div>
</div>

<!-- Delete Confirmation Modal -->
<div class="modal fade" id="deleteConfirmModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Confirm Deletion</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <p>Are you sure you want to delete this label?</p>
                <input type="hidden" id="deleteIp">
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-danger" id="confirmDelete">Delete</button>
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
    $(document).ready(function() {
        // Label search functionality
        $("#labelSearch").on("keyup", function() {
            var value = $(this).val().toLowerCase();
            $("#labelTable tbody tr").filter(function() {
                $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
            });
        });
        
        // Add label
        $('#addLabel').click(function() {
            $.ajax({
                type: 'POST',
                url: '/update-label',
                data: $('#addLabelForm').serialize(),
                success: function(response) {
                    if (response.success) {
                        $('#addLabelModal').modal('hide');
                        window.location.reload();
                    } else {
                        alert('Error adding label: ' + response.message);
                    }
                },
                error: function() {
                    alert('An error occurred while adding the label.');
                }
            });
        });
        
        // Edit label modal
        $('#editLabelModal').on('show.bs.modal', function (event) {
            var button = $(event.relatedTarget);
            var ip = button.data('ip');
            var label = button.data('label');
            
            var modal = $(this);
            modal.find('#editDeviceIp').val(ip);
            modal.find('#editDeviceLabel').val(label);
        });
        
        // Update label
        $('#updateLabel').click(function() {
            $.ajax({
                type: 'POST',
                url: '/update-label',
                data: $('#editLabelForm').serialize(),
                success: function(response) {
                    if (response.success) {
                        $('#editLabelModal').modal('hide');
                        window.location.reload();
                    } else {
                        alert('Error updating label: ' + response.message);
                    }
                },
                error: function() {
                    alert('An error occurred while updating the label.');
                }
            });
        });
        
        // Delete label button click
        $('.delete-label').click(function() {
            var ip = $(this).data('ip');
            $('#deleteIp').val(ip);
            $('#deleteConfirmModal').modal('show');
        });
        
        // Confirm delete
        $('#confirmDelete').click(function() {
            var ip = $('#deleteIp').val();
            $.ajax({
                type: 'POST',
                url: '/remove-label',
                data: { ip: ip },
                success: function(response) {
                    if (response.success) {
                        $('#deleteConfirmModal').modal('hide');
                        window.location.reload();
                    } else {
                        alert('Error removing label: ' + response.message);
                    }
                },
                error: function() {
                    alert('An error occurred while removing the label.');
                }
            });
        });
    });
</script>
{% endblock %}"""

        # Port scan template
        port_scan_html = """{% extends "base.html" %}

{% block title %}Port Scan - NetScan Dashboard{% endblock %}

{% block content %}
<div class="row">
    <div class="col-md-12">
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="mb-0">Port Scan: {{ ip }}</h5>
                <a href="/device/{{ ip }}" class="btn btn-sm btn-outline-primary">Back to Device</a>
            </div>
            <div class="card-body">
                {% if not nmap_available %}
                <div class="alert alert-warning">
                    <i class="bi bi-exclamation-triangle me-2"></i>
                    Port scanning requires nmap, which is not installed.
                    <div class="mt-2">
                        Install nmap with: <code>{{ 'brew install nmap' if platform == 'darwin' else 'apt install nmap' }}</code>
                    </div>
                </div>
                <a href="/devices" class="btn btn-primary">Back to Devices</a>
                {% else %}
                <form id="scanForm" action="/port-scan/{{ ip }}" method="post" class="mb-4">
                    <div class="row g-3 align-items-center">
                        <div class="col-auto">
                            <label for="portRange" class="col-form-label">Scan Type:</label>
                        </div>
                        <div class="col-auto">
                            <select class="form-select" id="scanType" name="scan_type">
                                <option value="standard" selected>Standard (Common Ports)</option>
                                <option value="deep">Deep Scan (More Ports, Slower)</option>
                            </select>
                        </div>
                        <div class="col-auto">
                            <button type="submit" id="scanButton" class="btn btn-primary">
                                <i class="bi bi-search me-2"></i>Start Scan
                            </button>
                        </div>
                    </div>
                </form>
                
                <div id="scanStatus">
                    {% if scanning %}
                    <div class="alert alert-info">
                        <div class="spinner-border spinner-border-sm me-2" role="status"></div>
                        <span>Scanning in progress...</span>
                    </div>
                    {% elif ports %}
                    <div class="alert alert-success">
                        <i class="bi bi-check-circle me-2"></i>
                        <span>Scan completed - {{ ports|length }} open ports found</span>
                    </div>
                    {% endif %}
                </div>
                
                {% if ports %}
                <div class="card mt-3">
                    <div class="card-header">
                        <h6 class="mb-0">Scan Results</h6>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>Port</th>
                                        <th>Service</th>
                                        <th>Possible Applications</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for port, service in ports.items() %}
                                    {% if port != 'error' and port != 'detailed' %}
                                    <tr>
                                        <td><strong>{{ port }}</strong></td>
                                        <td>{{ service }}</td>
                                        <td>
                                            {% if port|int == 22 %}
                                            SSH, SFTP - Secure shell for remote access
                                            {% elif port|int == 80 %}
                                            HTTP, Web Server - Hypertext Transfer Protocol
                                            {% elif port|int == 443 %}
                                            HTTPS, Secure Web Server - Encrypted web traffic
                                            {% elif port|int == 21 %}
                                            FTP - File Transfer Protocol
                                            {% elif port|int == 23 %}
                                            Telnet - Remote terminal access (insecure)
                                            {% elif port|int == 25 %}
                                            SMTP, Mail Server - Email sending
                                            {% elif port|int == 53 %}
                                            DNS - Domain Name System
                                            {% elif port|int == 110 %}
                                            POP3 - Post Office Protocol (email retrieval)
                                            {% elif port|int == 143 %}
                                            IMAP - Internet Message Access Protocol (email)
                                            {% elif port|int == 3306 %}
                                            MySQL Database - Open source database
                                            {% elif port|int == 5432 %}
                                            PostgreSQL Database - Open source database
                                            {% elif port|int == 8080 %}
                                            Web Server, Proxy - Alternate HTTP port
                                            {% elif port|int == 1433 %}
                                            Microsoft SQL Server - Database
                                            {% elif port|int == 3389 %}
                                            Remote Desktop Protocol (RDP) - Windows remote access
                                            {% elif port|int == 5900 or port|int == 5901 %}
                                            VNC Remote Access - Virtual Network Computing
                                            {% elif port|int == 6379 %}
                                            Redis - In-memory data structure store
                                            {% elif port|int == 27017 %}
                                            MongoDB - NoSQL database
                                            {% elif port|int == 139 or port|int == 445 %}
                                            SMB, Windows File Sharing - Server Message Block
                                            {% elif port|int == 548 %}
                                            AFP - Apple Filing Protocol for file sharing
                                            {% elif port|int == 631 %}
                                            IPP - Internet Printing Protocol
                                            {% elif port|int == 5000 %}
                                            UPnP - Universal Plug and Play / Flask apps
                                            {% elif port|int == 8000 %}
                                            Common web development port (Django, etc.)
                                            {% elif port|int == 8888 %}
                                            Jupyter Notebook - Web-based development
                                            {% elif port|int == 9000 %}
                                            PHP-FPM, Web applications
                                            {% elif port|int == 1080 %}
                                            SOCKS Proxy - Socket Secure protocol
                                            {% elif port|int == 1521 %}
                                            Oracle Database - Enterprise database
                                            {% elif port|int == 3000 %}
                                            Development servers (React, Node.js)
                                            {% elif port|int == 5353 %}
                                            mDNS - Multicast DNS, used by Bonjour/Avahi
                                            {% elif port|int == 7000 %}
                                            AirPlay - Apple media streaming
                                            {% elif port|int == 8443 %}
                                            HTTPS Alt - Secure web on alternate port
                                            {% elif port|int == 9090 %}
                                            Prometheus, Cockpit web console
                                            {% elif port|int == 9100 %}
                                            Printer, Node Exporter - Metrics collection
                                            {% elif port|int == 111 %}
                                            RPC - Remote Procedure Call
                                            {% elif port|int == 2049 %}
                                            NFS - Network File System
                                            {% elif port|int == 9200 %}
                                            Elasticsearch - Search engine
                                            {% elif port|int == 2375 or port|int == 2376 %}
                                            Docker - Container management
                                            {% elif port|int == 5222 %}
                                            XMPP - Extensible Messaging and Presence Protocol
                                            {% elif port|int == 5060 or port|int == 5061 %}
                                            SIP - Session Initiation Protocol (VoIP)
                                            {% elif port|int == 123 %}
                                            NTP - Network Time Protocol
                                            {% elif port|int == 161 or port|int == 162 %}
                                            SNMP - Simple Network Management Protocol
                                            {% elif port|int == 554 %}
                                            RTSP - Real Time Streaming Protocol
                                            {% elif port|int == 1900 %}
                                            SSDP - Simple Service Discovery Protocol (UPnP)
                                            {% elif port|int == 67 or port|int == 68 %}
                                            DHCP - Dynamic Host Configuration Protocol
                                            {% else %}
                                            Custom service or application
                                            {% endif %}
                                        </td>
                                    </tr>
                                    {% endif %}
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                {% elif not scanning %}
                <div class="alert alert-secondary">
                    <i class="bi bi-info-circle me-2"></i>
                    Start a port scan to discover open ports and services.
                </div>
                {% endif %}
                {% endif %}
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
    $(document).ready(function() {
        $('#scanForm').submit(function(e) {
            e.preventDefault();
            
            // Update UI to show scanning
            $('#scanStatus').html(`
                <div class="alert alert-info">
                    <div class="spinner-border spinner-border-sm me-2" role="status"></div>
                    <span>Scanning in progress...</span>
                </div>
            `);
            
            // Disable button
            $('#scanButton').prop('disabled', true);
            
            // Submit the form via AJAX
            $.ajax({
                type: 'POST',
                url: $(this).attr('action'),
                data: $(this).serialize(),
                success: function(response) {
                    if (response.success) {
                        // Poll for scan completion
                        pollScanStatus();
                    } else {
                        $('#scanStatus').html(`
                            <div class="alert alert-danger">
                                <i class="bi bi-exclamation-triangle me-2"></i>
                                <span>Error: ${response.message}</span>
                            </div>
                        `);
                        $('#scanButton').prop('disabled', false);
                    }
                },
                error: function() {
                    $('#scanStatus').html(`
                        <div class="alert alert-danger">
                            <i class="bi bi-exclamation-triangle me-2"></i>
                            <span>An error occurred while starting the scan.</span>
                        </div>
                    `);
                    $('#scanButton').prop('disabled', false);
                }
            });
        });
        
        function pollScanStatus() {
            $.ajax({
                url: window.location.pathname + '/status',
                success: function(response) {
                    if (response.scanning) {
                        // Still scanning, poll again in 1 second
                        setTimeout(pollScanStatus, 1000);
                    } else {
                        // Scan complete, show results without reloading
                        console.log("Scan complete. Results:", response);
                        
                        // Update status
                        let statusHtml = '';
                        if (response.error) {
                            statusHtml = `
                                <div class="alert alert-danger">
                                    <i class="bi bi-exclamation-triangle me-2"></i>
                                    <span>Error: ${response.error}</span>
                                </div>
                            `;
                        } else if (response.port_count === 0) {
                            statusHtml = `
                                <div class="alert alert-warning">
                                    <i class="bi bi-info-circle me-2"></i>
                                    <span>Scan completed - No open ports found</span>
                                </div>
                            `;
                        } else {
                            statusHtml = `
                                <div class="alert alert-success">
                                    <i class="bi bi-check-circle me-2"></i>
                                    <span>Scan completed - ${response.port_count} open ports found</span>
                                </div>
                            `;
                            
                            // Add results table
                            statusHtml += `
                                <div class="card mt-3">
                                    <div class="card-header">
                                        <h6 class="mb-0">Scan Results</h6>
                                    </div>
                                    <div class="card-body">
                                        <div class="table-responsive">
                                            <table class="table table-striped">
                                                <thead>
                                                    <tr>
                                                        <th>Port</th>
                                                        <th>Service</th>
                                                        <th>Details</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                            `;
                            
                            // Loop through ports
                            for (const [port, info] of Object.entries(response.ports)) {
                                statusHtml += `
                                    <tr>
                                        <td><strong>${port}</strong></td>
                                        <td>${info.name || info}</td>
                                        <td>${info.product ? info.product + ' ' + info.version : ''}</td>
                                    </tr>
                                `;
                            }
                            
                            statusHtml += `
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>
                                </div>
                            `;
                        }
                        
                        $('#scanStatus').html(statusHtml);
                        $('#scanButton').prop('disabled', false);
                    }
                },
                error: function() {
                    // Error occurred, stop polling
                    $('#scanStatus').html(`
                        <div class="alert alert-danger">
                            <i class="bi bi-exclamation-triangle me-2"></i>
                            <span>An error occurred while checking scan status.</span>
                        </div>
                    `);
                    $('#scanButton').prop('disabled', false);
                }
            });
        }
    });
</script>
{% endblock %}"""

        # Ping result template
        ping_result_html = """{% extends "base.html" %}

{% block title %}Ping Result - NetScan Dashboard{% endblock %}

{% block content %}
<div class="row">
    <div class="col-md-12">
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="mb-0">Ping Result: {{ ip }}</h5>
                <a href="/device/{{ ip }}" class="btn btn-sm btn-outline-primary">Back to Device</a>
            </div>
            <div class="card-body">
                {% if success %}
                <div class="alert alert-success">
                    <i class="bi bi-check-circle me-2"></i>
                    <span>Ping to {{ ip }} successful</span>
                </div>
                {% else %}
                <div class="alert alert-danger">
                    <i class="bi bi-exclamation-triangle me-2"></i>
                    <span>Ping to {{ ip }} failed</span>
                    {% if error %}
                    <div class="mt-2">
                        <strong>Error:</strong> {{ error }}
                    </div>
                    {% endif %}
                </div>
                {% endif %}
                
                {% if output %}
                <div class="card mt-3">
                    <div class="card-header">
                        <h6 class="mb-0">Ping Output</h6>
                    </div>
                    <div class="card-body">
                        <pre class="bg-light p-3">{{ output }}</pre>
                    </div>
                </div>
                {% endif %}
                
                <div class="mt-3">
                    <a href="/device/{{ ip }}" class="btn btn-primary">Back to Device</a>
                    <a href="/" class="btn btn-outline-secondary">Back to Dashboard</a>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}"""
        
        # Write templates to files
        with open(os.path.join(template_dir, 'base.html'), 'w') as f:
            f.write(base_html)
        with open(os.path.join(template_dir, 'index.html'), 'w') as f:
            f.write(index_html)
        with open(os.path.join(template_dir, 'devices.html'), 'w') as f:
            f.write(devices_html)
        with open(os.path.join(template_dir, 'device_detail.html'), 'w') as f:
            f.write(device_detail_html)
        with open(os.path.join(template_dir, 'labels.html'), 'w') as f:
            f.write(labels_html)
        with open(os.path.join(template_dir, 'port_scan.html'), 'w') as f:
            f.write(port_scan_html)
        with open(os.path.join(template_dir, 'ping_result.html'), 'w') as f:
            f.write(ping_result_html)
    
    def _register_routes(self):
        """Register routes for the web dashboard"""
        app = self.app
        
        @app.route('/')
        def index():
            """Index page route"""
            return render_template('index.html', 
                                  network_info=self.network_info,
                                  devices=self.devices,
                                  scanning=self.scanning,
                                  last_scan_time=self.last_scan_time)
        
        @app.route('/scan', methods=['POST'])
        def scan():
            """Start a network scan"""
            if self.scanning:
                return jsonify({'success': False, 'message': 'A scan is already in progress'})
            
            # Get scan parameters
            network_cidr = request.form.get('network_cidr')
            health_check = request.form.get('health_check') == 'on'
            
            # Start scan in a background thread
            threading.Thread(target=self._run_scan, args=(network_cidr, health_check)).start()
            
            return jsonify({'success': True})
        
        @app.route('/scan-status')
        def scan_status():
            """Check scan status"""
            return jsonify({'scanning': self.scanning})
        
        @app.route('/devices')
        def devices():
            """Devices page route"""
            # Add label info to devices
            devices_with_labels = []
            for device in self.devices:
                device_copy = device.copy()
                device_copy['label'] = self.identifier.get_device_label(device['ip'])
                devices_with_labels.append(device_copy)
                
            return render_template('devices.html', devices=devices_with_labels)
        
        @app.route('/labels')
        def labels():
            """Labels page route"""
            return render_template('labels.html', 
                                  labels=self.identifier.device_labels,
                                  devices=self.devices)
        
        @app.route('/update-label', methods=['POST'])
        def update_label():
            """Update a device label"""
            ip = request.form.get('ip')
            label = request.form.get('label')
            
            if not ip:
                return jsonify({'success': False, 'message': 'IP address is required'})
            
            if self.identifier.add_device_label(ip, label):
                return jsonify({'success': True})
            else:
                return jsonify({'success': False, 'message': 'Failed to update label'})
        
        @app.route('/remove-label', methods=['POST'])
        def remove_label():
            """Remove a device label"""
            ip = request.form.get('ip')
            
            if not ip:
                return jsonify({'success': False, 'message': 'IP address is required'})
            
            if self.identifier.remove_device_label(ip):
                return jsonify({'success': True})
            else:
                return jsonify({'success': False, 'message': 'Failed to remove label'})
        
        @app.route('/device/<ip>')
        def device_detail(ip):
            """Device detail page route"""
            try:
                device = next((d for d in self.devices if d['ip'] == ip), None)
                
                if device:
                    # Add label info
                    device_copy = device.copy()
                    device_copy['label'] = self.identifier.get_device_label(ip)
                    
                    # Make sure ports is a dict if it exists
                    if 'ports' in device_copy and not isinstance(device_copy['ports'], dict):
                        device_copy['ports'] = {}
                    
                    # Make sure we have the most up-to-date vendor information
                    if device_copy.get('mac') and device_copy.get('mac') != 'Unknown':
                        device_copy['vendor'] = self.identifier.get_mac_vendor(device_copy['mac'])
                    
                    # Check online status if needed
                    if 'status' not in device_copy or device_copy['status'] == 'Unknown':
                        try:
                            import ping3
                            result = ping3.ping(ip, timeout=1)
                            if result is not None:
                                device_copy['status'] = "Online"
                            else:
                                device_copy['status'] = "Offline"
                        except Exception as e:
                            print(f"Error pinging device: {str(e)}")
                            device_copy['status'] = "Unknown"
                    
                    # Make sure device_type is set
                    if not device_copy.get('device_type') or device_copy['device_type'] == 'Unknown':
                        if device_copy.get('type'):
                            device_copy['device_type'] = device_copy['type']
                        else:
                            # Determine device type based on available information
                            device_copy['device_type'] = self.identifier.determine_device_type(
                                device_copy.get('vendor', 'Unknown'),
                                device_copy.get('ports', {}),
                                device_copy.get('hostname', None)
                            )
                    
                    return render_template('device_detail.html', device=device_copy)
                else:
                    # If device not found, create a basic info object with the IP and try to get some information
                    hostname = None
                    try:
                        hostname = socket.getfqdn(ip)
                        if hostname == ip:  # If hostname is the same as IP, resolution failed
                            hostname = 'Unknown'
                    except Exception:
                        hostname = 'Unknown'
                    
                    # Try to ping the device
                    status = "Unknown"
                    try:
                        import ping3
                        result = ping3.ping(ip, timeout=1)
                        if result is not None:
                            status = "Online"
                        else:
                            status = "Offline"
                    except Exception as e:
                        print(f"Error pinging device: {str(e)}")
                    
                    # Create a basic device object
                    basic_device = {
                        'ip': ip,
                        'mac': 'Unknown',
                        'hostname': hostname,
                        'device_type': 'Unknown Device',
                        'vendor': 'Unknown',
                        'status': status,
                        'label': self.identifier.get_device_label(ip)
                    }
                    
                    return render_template('device_detail.html', device=basic_device)
            except Exception as e:
                print(f"Error in device_detail route: {str(e)}")
                traceback.print_exc()
                # Return a simple error page
                return f"""
                <html>
                    <head><title>Error</title></head>
                    <body>
                        <h1>Error displaying device details</h1>
                        <p>{str(e)}</p>
                        <p><a href="/">Back to Dashboard</a></p>
                    </body>
                </html>
                """
        
        @app.route('/port-scan/<ip>', methods=['GET'])
        def port_scan_page(ip):
            """Port scan page route"""
            try:
                device = next((d for d in self.devices if d['ip'] == ip), None)
                ports = {}
                
                # If we have this device, use its ports if available
                if device:
                    if 'open_ports' in device and isinstance(device['open_ports'], dict):
                        ports = device['open_ports']
                    elif 'ports' in device and isinstance(device['ports'], dict):
                        ports = device['ports']
                
                # Check if a scan is currently running for this IP
                is_scanning = ip in self.port_scanning and self.port_scanning[ip]
                
                print(f"Rendering port scan page for {ip}. Is Scanning: {is_scanning}, Ports: {ports}")
                
                return render_template('port_scan.html', 
                                      ip=ip,
                                      ports=ports,
                                      scanning=is_scanning,
                                      nmap_available=self.identifier.nmap_available,
                                      platform=os.name)
            except Exception as e:
                print(f"Error in port_scan_page route: {str(e)}")
                traceback.print_exc()
                # Return a simple error page
                return f"""
                <html>
                    <head><title>Error</title></head>
                    <body>
                        <h1>Error displaying port scan page</h1>
                        <p>{str(e)}</p>
                        <p><a href="/">Back to Dashboard</a></p>
                    </body>
                </html>
                """
        
        @app.route('/port-scan/<ip>', methods=['POST'])
        def start_port_scan(ip):
            """Start a port scan"""
            try:
                # Check if a network scan is in progress
                if self.scanning:
                    return jsonify({'success': False, 'message': 'A network scan is already in progress'})
                
                # Check if a port scan is already running for this IP
                if ip in self.port_scanning and self.port_scanning[ip]:
                    return jsonify({'success': False, 'message': f'A port scan for {ip} is already in progress'})
                
                if not self.identifier.nmap_available:
                    return jsonify({'success': False, 'message': 'Port scanning requires nmap, which is not installed'})
                
                # Get scan type
                scan_type = request.form.get('scan_type', 'standard')
                
                # Define port range based on scan type
                port_range = None
                if scan_type == 'deep':
                    port_range = "1-1024,1433,1521,3000,3306,3389,5000,5432,5900,5901,6379,8000-8100,9000-9200,27017"
                
                # Mark this IP as being scanned
                self.port_scanning[ip] = True
                
                # Start scan in a background thread
                threading.Thread(target=self._run_port_scan, args=(ip, port_range)).start()
                
                return jsonify({'success': True})
            except Exception as e:
                print(f"Error starting port scan: {str(e)}")
                traceback.print_exc()
                return jsonify({'success': False, 'message': f'Error starting scan: {str(e)}'})
        
        @app.route('/port-scan/<ip>/status')
        def port_scan_status(ip):
            """Check port scan status"""
            try:
                # Check if still scanning
                is_scanning = ip in self.port_scanning and self.port_scanning[ip]
                
                # Get port information if scan has completed
                ports = {}
                if not is_scanning:
                    # Try to find the device
                    device = next((d for d in self.devices if d['ip'] == ip), None)
                    if device:
                        # Try open_ports first, then ports
                        if 'open_ports' in device and isinstance(device['open_ports'], dict):
                            raw_ports = device['open_ports']
                        elif 'ports' in device and isinstance(device['ports'], dict):
                            raw_ports = device['ports']
                        else:
                            raw_ports = {}
                        
                        # Clean up ports data for display
                        for port_key, port_info in raw_ports.items():
                            # Skip non-port keys like 'detailed' or 'error'
                            if port_key in ['detailed', 'error']:
                                continue
                                
                            # Process different formats of port info
                            if isinstance(port_info, dict):
                                # Extract name for display
                                if 'name' in port_info:
                                    service_name = port_info['name']
                                    if port_info.get('product'):
                                        service_name += f" ({port_info['product']})"
                                        if port_info.get('version'):
                                            service_name += f" {port_info['version']}"
                                    ports[port_key] = service_name
                                else:
                                    ports[port_key] = "unknown"
                            elif isinstance(port_info, str):
                                # Use the string directly
                                ports[port_key] = port_info
                            else:
                                # Fallback for any other data type
                                ports[port_key] = str(port_info)
                
                port_count = len(ports)
                print(f"Port scan status for {ip}: scanning={is_scanning}, ports={port_count}")
                
                # Return status and port data for AJAX updates
                return jsonify({
                    'scanning': is_scanning,
                    'ports': ports,
                    'port_count': port_count,
                    'scan_type': 'deep' if port_count > 10 else 'standard'
                })
            except Exception as e:
                print(f"Error in port_scan_status: {str(e)}")
                traceback.print_exc()
                return jsonify({
                    'scanning': False,
                    'error': str(e),
                    'port_count': 0
                })
        
        @app.route('/ping/<ip>')
        def ping_device(ip):
            """Ping a device and return the result"""
            import subprocess
            
            try:
                # Run ping command
                command = f"ping -c 4 {ip}"
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                output, error = process.communicate()
                
                # Parse output
                output_str = output.decode('utf-8')
                error_str = error.decode('utf-8') if error else None
                
                return render_template('ping_result.html', 
                                      ip=ip,
                                      success=process.returncode == 0,
                                      output=output_str,
                                      error=error_str)
            except Exception as e:
                print(f"Error during ping: {str(e)}")
                traceback.print_exc()
                return render_template('ping_result.html',
                                      ip=ip,
                                      success=False,
                                      error=str(e))
    
    def _run_scan(self, network_cidr, health_check):
        """Run a network scan in the background"""
        self.scanning = True
        try:
            # Get network info if not already available
            if not self.network_info:
                self.network_info = get_network_info()
            
            # Use provided network CIDR or default from network info
            if network_cidr:
                scan_network = network_cidr
            else:
                scan_network = self.network_info['network_cidr']
            
            # Discover devices
            devices = discover_devices(
                network_cidr=scan_network,
                check_health_status=health_check,
                interface=self.network_info['interface']
            )
            
            # Identify devices
            for device in devices:
                # Identify the device
                device_info = self.identifier.identify_device(
                    device['ip'], 
                    device['mac'], 
                    hostname=device.get('hostname')
                )
                
                # Add health info if it was collected
                if 'health' in device:
                    device_info['health'] = device.get('health')
                    
                # Add gateway flag if applicable
                if device.get('is_gateway', False):
                    device_info['is_gateway'] = True
                    
                # Update the device in the list with full identification
                for i, d in enumerate(devices):
                    if d['ip'] == device_info['ip']:
                        devices[i] = device_info
                        break
            
            # Update devices list
            self.devices = devices
            
            # Set last scan time
            self.last_scan_time = time.strftime('%Y-%m-%d %H:%M:%S')
        except Exception as e:
            print(f"Error during scan: {str(e)}")
        finally:
            self.scanning = False
    
    def _run_port_scan(self, ip, port_range=None):
        """Run a port scan in the background"""
        try:
            print(f"Starting port scan for {ip} with range: {port_range if port_range else 'default'}")
            
            # Scan ports - handle with error checking
            try:
                scan_result = self.identifier.scan_ports(ip, ports=port_range)
                print(f"Raw scan result for {ip}: {scan_result}")
                
                # Validate scan result is a dictionary
                if isinstance(scan_result, dict):
                    if "error" in scan_result:
                        print(f"Scan error for {ip}: {scan_result['error']}")
                        ports = {"error": scan_result['error']}
                    else:
                        # Process port scan results
                        ports = {}
                        for port_key, port_info in scan_result.items():
                            # Skip non-port keys like 'detailed'
                            if port_key in ['detailed', 'error']:
                                continue
                                
                            # Convert port to string if it's not already
                            port_str = str(port_key)
                            
                            # Handle different possible formats of port info
                            if isinstance(port_info, dict):
                                # Extract name for display
                                if 'name' in port_info:
                                    service_name = port_info['name']
                                    if port_info.get('product'):
                                        service_name += f" ({port_info['product']})"
                                        if port_info.get('version'):
                                            service_name += f" {port_info['version']}"
                                    ports[port_str] = service_name
                                else:
                                    ports[port_str] = "unknown"
                            elif isinstance(port_info, str):
                                # Use the string directly
                                ports[port_str] = port_info
                            else:
                                # Fallback for any other data type
                                ports[port_str] = str(port_info)
                                
                        # If we have no ports after processing, might be empty result
                        if not ports and 'detailed' not in scan_result:
                            print(f"No open ports found for {ip}")
                else:
                    print(f"Invalid scan result type: {type(scan_result)}")
                    ports = {}
            except Exception as scan_error:
                print(f"Exception during scan_ports: {str(scan_error)}")
                traceback.print_exc()
                ports = {"error": str(scan_error)}
            
            # Log the port scan result
            if "error" in ports:
                print(f"Port scan failed for {ip}: {ports['error']}")
            else:
                print(f"Port scan results for {ip}: found {len(ports)} ports")
                for port, info in ports.items():
                    print(f"  Port {port}: {info}")
            
            # Update device info if it exists
            device_updated = False
            for i, device in enumerate(self.devices):
                if device['ip'] == ip:
                    # Store in both locations to ensure compatibility
                    self.devices[i]['ports'] = ports
                    self.devices[i]['open_ports'] = ports
                    
                    # Update device type if we found open ports
                    if ports and not "error" in ports and len(ports) > 0:
                        # Create a clean copy of ports for device type determination
                        device_type = self.identifier.determine_device_type(
                            device.get('vendor', 'Unknown'),
                            ports,
                            device.get('hostname')
                        )
                        self.devices[i]['device_type'] = device_type
                        self.devices[i]['type'] = device_type
                    
                    device_updated = True
                    break
            
            # If device not in list, add a basic entry
            if not device_updated:
                print(f"Adding new device for {ip} with scan results")
                
                # Try to identify the device with the port information
                hostname = None
                try:
                    hostname = socket.getfqdn(ip)
                    if hostname == ip:  # If hostname is the same as IP, resolution failed
                        hostname = 'Unknown'
                except Exception:
                    hostname = 'Unknown'
                
                # Get MAC address if possible (will be Unknown on many systems)
                mac = 'Unknown'
                try:
                    # This is a simplified approach and might not work on all systems
                    import subprocess
                    try:
                        output = subprocess.check_output(['arp', '-n', ip], text=True)
                        mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', output)
                        if mac_match:
                            mac = mac_match.group(0)
                    except subprocess.SubprocessError:
                        pass  # Silently handle subprocess errors
                except Exception:
                    pass  # Silently handle any other errors
                
                # Get vendor information
                vendor = 'Unknown'
                if mac != 'Unknown':
                    vendor = self.identifier.get_mac_vendor(mac)
                
                # Determine device type based on ports
                device_type = self.identifier.determine_device_type(vendor, ports, hostname)
                
                new_device = {
                    'ip': ip,
                    'mac': mac,
                    'hostname': hostname,
                    'device_type': device_type,
                    'type': device_type,
                    'vendor': vendor,
                    'status': 'Online',  # If we can scan ports, it's online
                    'ports': ports,
                    'open_ports': ports
                }
                self.devices.append(new_device)
                
        except Exception as e:
            print(f"Error during port scan processing: {str(e)}")
            traceback.print_exc()
        finally:
            # Mark this IP as no longer being scanned
            print(f"Marking port scan complete for {ip}")
            if ip in self.port_scanning:
                self.port_scanning[ip] = False
    
    def run(self):
        """Run the web dashboard"""
        try:
            # Get initial network info
            self.network_info = get_network_info()
            
            # Print startup information
            if self.port != self.requested_port:
                print(f"\n🌐 Port {self.requested_port} was in use. Starting Web Dashboard on http://127.0.0.1:{self.port}")
            else:
                print(f"\n🌐 Starting Web Dashboard on http://127.0.0.1:{self.port}")
            print("Press Ctrl+C to stop the server\n")
            
            # Open web browser with a delay
            threading.Timer(1.5, lambda: webbrowser.open(f"http://127.0.0.1:{self.port}")).start()
            
            # Run the Flask app
            self.app.run(host='0.0.0.0', port=self.port, debug=False)
            
            return 0
        except KeyboardInterrupt:
            print("\nWeb dashboard stopped.")
            return 130
        except Exception as e:
            print(f"\nError: {str(e)}")
            return 1