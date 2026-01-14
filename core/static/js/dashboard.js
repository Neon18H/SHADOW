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
                    color: '#e5edf7',
                    boxWidth: 12,
                }
            },
        },
        scales: {
            x: { ticks: { color: '#8f9bb3' }, grid: { color: 'rgba(255,255,255,0.06)' } },
            y: { ticks: { color: '#8f9bb3' }, grid: { color: 'rgba(255,255,255,0.06)' } },
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
                        borderColor: '#ff8c42',
                        backgroundColor: 'rgba(255, 140, 66, 0.18)',
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
                backgroundColor: ['#43aa8b', '#f9c74f', '#f3722c', '#e63946'],
                borderColor: 'rgba(255,255,255,0.08)'
            }]
        }, { scales: {} });

        renderChart('chartPipeline', 'bar', {
            labels: pipeline.labels,
            datasets: [{
                label: 'Pipeline',
                data: pipeline.data,
                backgroundColor: 'rgba(255, 140, 66, 0.5)',
                borderColor: '#ff8c42',
                borderWidth: 1,
            }]
        }, {
            indexAxis: 'y',
            scales: {
                x: { ticks: { color: '#8f9bb3' }, grid: { color: 'rgba(255,255,255,0.06)' } },
                y: { ticks: { color: '#e5edf7' }, grid: { display: false } },
            }
        });

        renderChart('chartCoverage', 'line', {
            labels: coverage.labels,
            datasets: [{
                label: 'Coverage %',
                data: coverage.data,
                borderColor: '#ffb26b',
                backgroundColor: 'rgba(255, 178, 107, 0.18)',
                tension: 0.35,
                fill: true,
            }]
        });
    });

    loadAlertsOverTime(7);
})();
