(() => {
    const body = document.body;
    const toggle = document.querySelector('[data-sidebar-toggle]');
    const overlay = document.querySelector('[data-sidebar-overlay]');

    if (toggle && overlay) {
        const closeSidebar = () => body.classList.remove('sidebar-open');
        toggle.addEventListener('click', () => body.classList.toggle('sidebar-open'));
        overlay.addEventListener('click', closeSidebar);
    }

    const toastContainer = document.getElementById('toastContainer');
    window.showToast = (message, variant = 'primary') => {
        if (!toastContainer || !window.bootstrap) return;
        const toastEl = document.createElement('div');
        toastEl.className = `toast align-items-center text-bg-${variant} border-0`;
        toastEl.setAttribute('role', 'alert');
        toastEl.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">${message}</div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>`;
        toastContainer.appendChild(toastEl);
        const toast = new bootstrap.Toast(toastEl, { delay: 4000 });
        toast.show();
    };

    document.querySelectorAll('[data-table-search]').forEach((input) => {
        input.addEventListener('input', () => {
            const table = document.getElementById(input.dataset.tableSearch);
            if (!table) return;
            const filter = input.value.toLowerCase();
            table.querySelectorAll('tbody tr').forEach((row) => {
                row.style.display = row.innerText.toLowerCase().includes(filter) ? '' : 'none';
            });
        });
    });

    document.querySelectorAll('[data-skeleton]').forEach((el) => {
        el.classList.add('skeleton');
        setTimeout(() => el.classList.remove('skeleton'), 800);
    });

    const drawer = document.querySelector('[data-evidence-drawer]');
    const drawerTabs = document.querySelectorAll('[data-drawer-tab]');
    document.querySelectorAll('[data-drawer-open]').forEach((btn) => {
        btn.addEventListener('click', () => body.classList.add('drawer-open'));
    });
    document.querySelectorAll('[data-drawer-close]').forEach((btn) => {
        btn.addEventListener('click', () => body.classList.remove('drawer-open'));
    });
    drawerTabs.forEach((tab) => {
        tab.addEventListener('click', () => {
            const target = tab.dataset.drawerTab;
            drawerTabs.forEach((item) => item.classList.remove('active'));
            tab.classList.add('active');
            drawer?.querySelectorAll('[data-drawer-pane]').forEach((pane) => {
                pane.classList.toggle('active', pane.dataset.drawerPane === target);
            });
        });
    });

    document.querySelectorAll('.btn-soc').forEach((button) => {
        button.addEventListener('click', () => {
            button.classList.add('pulse');
            setTimeout(() => button.classList.remove('pulse'), 250);
        });
    });

    const funnel = document.querySelector('[data-funnel]');
    if (funnel) {
        funnel.addEventListener('mousemove', (event) => {
            const rect = funnel.getBoundingClientRect();
            const offsetX = ((event.clientX - rect.left) / rect.width - 0.5) * 10;
            funnel.style.transform = `rotateY(${offsetX}deg)`;
        });
        funnel.addEventListener('mouseleave', () => {
            funnel.style.transform = 'rotateY(0deg)';
        });
    }

    const autoRefreshToggle = document.querySelector('[data-auto-refresh]');
    let refreshInterval;
    const refreshSummary = () => {
        fetch('/api/metrics/summary')
            .then((res) => res.json())
            .then((data) => {
                document.querySelectorAll('[data-metric]').forEach((el) => {
                    const key = el.dataset.metric;
                    if (data[key] !== undefined && data[key] !== null) {
                        el.textContent = data[key];
                    }
                });
            })
            .catch(() => {
                showToast('No se pudo actualizar el resumen', 'danger');
            });
    };
    if (autoRefreshToggle) {
        autoRefreshToggle.addEventListener('change', () => {
            if (autoRefreshToggle.checked) {
                refreshSummary();
                refreshInterval = setInterval(refreshSummary, 15000);
            } else if (refreshInterval) {
                clearInterval(refreshInterval);
            }
        });
    }

    const chartElements = {
        severity: document.getElementById('chartSeverity'),
        alerts: document.getElementById('chartAlertsOverTime'),
        coverage: document.getElementById('chartCoverage'),
        pipeline: document.getElementById('chartPipeline'),
    };

    if (!window.Chart || !chartElements.severity) return;

    let chartAlertsOverTime;

    const baseConfig = {
        plugins: {
            legend: {
                labels: {
                    color: '#e8eef7',
                    boxWidth: 12,
                }
            },
        },
        scales: {
            x: { ticks: { color: '#8a97b3' }, grid: { color: 'rgba(255,255,255,0.06)' } },
            y: { ticks: { color: '#8a97b3' }, grid: { color: 'rgba(255,255,255,0.06)' } },
        }
    };

    const renderChart = (id, type, data, options = {}) => {
        const ctx = document.getElementById(id);
        if (!ctx) return null;
        return new Chart(ctx, {
            type,
            data,
            options: { ...baseConfig, ...options }
        });
    };

    const loadAlertsOverTime = (days) => {
        fetch(`/api/metrics/alerts-over-time?days=${days}`)
            .then(res => res.json())
            .then(data => {
                const dataset = {
                    labels: data.labels,
                    datasets: [{
                        label: 'Alertas',
                        data: data.data,
                        borderColor: '#ff8a3d',
                        backgroundColor: 'rgba(255, 138, 61, 0.18)',
                        tension: 0.4,
                        fill: true,
                    }]
                };
                if (chartAlertsOverTime) {
                    chartAlertsOverTime.data = dataset;
                    chartAlertsOverTime.update();
                } else {
                    chartAlertsOverTime = renderChart('chartAlertsOverTime', 'line', dataset);
                }
            });
    };

    document.querySelectorAll('[data-alerts-range]').forEach((button) => {
        button.addEventListener('click', () => loadAlertsOverTime(button.dataset.alertsRange));
    });

    Promise.all([
        fetch('/api/metrics/alerts-by-severity').then(res => res.json()),
        fetch('/api/metrics/top-rules').then(res => res.json()),
        fetch('/api/metrics/mttr-trend?days=14').then(res => res.json())
    ]).then(([severity, pipeline, coverage]) => {
        renderChart('chartSeverity', 'doughnut', {
            labels: severity.labels,
            datasets: [{
                data: severity.data,
                backgroundColor: ['#22c55e', '#facc15', '#f97316', '#ef4444'],
                borderColor: 'rgba(255,255,255,0.08)'
            }]
        }, { scales: {} });

        renderChart('chartPipeline', 'bar', {
            labels: pipeline.labels,
            datasets: [{
                label: 'Pipeline',
                data: pipeline.data,
                backgroundColor: 'rgba(255, 138, 61, 0.5)',
                borderColor: '#ff8a3d',
                borderWidth: 1,
            }]
        }, {
            indexAxis: 'y',
            scales: {
                x: { ticks: { color: '#8a97b3' }, grid: { color: 'rgba(255,255,255,0.06)' } },
                y: { ticks: { color: '#e8eef7' }, grid: { display: false } },
            }
        });

        renderChart('chartCoverage', 'line', {
            labels: coverage.labels,
            datasets: [{
                label: 'Coverage %',
                data: coverage.data,
                borderColor: '#2dd4bf',
                backgroundColor: 'rgba(45, 212, 191, 0.16)',
                tension: 0.35,
                fill: true,
            }]
        });
    });

    loadAlertsOverTime(7);
})();
