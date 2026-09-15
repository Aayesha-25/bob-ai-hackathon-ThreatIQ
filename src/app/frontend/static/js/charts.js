/*
 * ARES — Threat Intelligence Command Center
 * Global Chart.js Configuration
 *
 * DEMO DATA ONLY
 * No real SIEM, network, or defence-system connectivity.
 */

(function () {
    "use strict";

    /* =========================================================
       Global Chart Defaults
       ========================================================= */

    if (typeof Chart === "undefined") {
        console.warn("ARES: Chart.js is not loaded.");
        return;
    }

    Chart.defaults.font.family =
        "Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif";

    Chart.defaults.font.size = 11;

    Chart.defaults.color = "#94a3b8";

    Chart.defaults.borderColor = "rgba(51, 65, 85, 0.55)";

    Chart.defaults.plugins.legend.labels.usePointStyle = true;

    Chart.defaults.plugins.legend.labels.boxWidth = 8;

    Chart.defaults.plugins.tooltip.backgroundColor = "#0f172a";

    Chart.defaults.plugins.tooltip.borderColor = "#334155";

    Chart.defaults.plugins.tooltip.borderWidth = 1;

    Chart.defaults.plugins.tooltip.titleColor = "#f8fafc";

    Chart.defaults.plugins.tooltip.bodyColor = "#cbd5e1";

    Chart.defaults.plugins.tooltip.padding = 10;

    Chart.defaults.plugins.tooltip.cornerRadius = 6;


    /* =========================================================
       Helper Functions
       ========================================================= */

    function getCanvas(id) {
        const canvas = document.getElementById(id);

        if (!canvas) {
            return null;
        }

        return canvas;
    }


    function destroyExistingChart(canvas) {

        if (!canvas) {
            return;
        }

        const existingChart = Chart.getChart(canvas);

        if (existingChart) {
            existingChart.destroy();
        }
    }


    function createGradient(ctx, color, alphaStart, alphaEnd) {

        const gradient = ctx.createLinearGradient(
            0,
            0,
            0,
            ctx.canvas.height
        );

        gradient.addColorStop(
            0,
            color.replace("ALPHA", alphaStart)
        );

        gradient.addColorStop(
            1,
            color.replace("ALPHA", alphaEnd)
        );

        return gradient;
    }


    /* =========================================================
       Alert Volume Chart
       ========================================================= */

    window.createAlertVolumeChart = function (
        canvasId = "alertVolumeChart",
        labels = [
            "00:00",
            "02:00",
            "04:00",
            "06:00",
            "08:00",
            "10:00",
            "12:00",
            "14:00",
            "16:00",
            "18:00",
            "20:00",
            "22:00"
        ],
        values = [
            42,
            55,
            38,
            64,
            81,
            96,
            74,
            112,
            128,
            101,
            86,
            72
        ]
    ) {

        const canvas = getCanvas(canvasId);

        if (!canvas) {
            return null;
        }

        destroyExistingChart(canvas);

        const ctx = canvas.getContext("2d");

        const gradient = createGradient(
            ctx,
            "rgba(34, 211, 238, ALPHA)",
            "0.28",
            "0.02"
        );

        return new Chart(ctx, {

            type: "line",

            data: {
                labels: labels,

                datasets: [
                    {
                        label: "Simulated Alerts",

                        data: values,

                        borderColor: "#22d3ee",

                        backgroundColor: gradient,

                        borderWidth: 2,

                        pointRadius: 2,

                        pointHoverRadius: 5,

                        pointBackgroundColor: "#22d3ee",

                        pointBorderColor: "#0f172a",

                        tension: 0.35,

                        fill: true
                    }
                ]
            },

            options: {

                responsive: true,

                maintainAspectRatio: false,

                interaction: {
                    intersect: false,
                    mode: "index"
                },

                plugins: {

                    legend: {
                        display: false
                    },

                    tooltip: {
                        callbacks: {
                            label: function (context) {
                                return (
                                    " Simulated alerts: " +
                                    context.parsed.y
                                );
                            }
                        }
                    }
                },

                scales: {

                    x: {
                        grid: {
                            display: false
                        },

                        ticks: {
                            color: "#64748b",
                            maxRotation: 0
                        }
                    },

                    y: {

                        beginAtZero: true,

                        grid: {
                            color: "rgba(51, 65, 85, 0.35)"
                        },

                        ticks: {
                            color: "#64748b"
                        }
                    }
                }
            }
        });
    };


    /* =========================================================
       Severity Distribution Chart
       ========================================================= */

    window.createSeverityChart = function (
        canvasId = "severityChart",
        values = [8, 24, 63, 117]
    ) {

        const canvas = getCanvas(canvasId);

        if (!canvas) {
            return null;
        }

        destroyExistingChart(canvas);

        const ctx = canvas.getContext("2d");

        return new Chart(ctx, {

            type: "doughnut",

            data: {

                labels: [
                    "Critical",
                    "High",
                    "Medium",
                    "Low"
                ],

                datasets: [
                    {
                        data: values,

                        backgroundColor: [
                            "#ef4444",
                            "#f59e0b",
                            "#3b82f6",
                            "#64748b"
                        ],

                        borderColor: "#0f172a",

                        borderWidth: 3,

                        hoverOffset: 5
                    }
                ]
            },

            options: {

                responsive: true,

                maintainAspectRatio: false,

                cutout: "68%",

                plugins: {

                    legend: {
                        position: "bottom",

                        labels: {
                            color: "#94a3b8",

                            padding: 16,

                            usePointStyle: true,

                            pointStyle: "circle"
                        }
                    },

                    tooltip: {

                        callbacks: {

                            label: function (context) {

                                const total =
                                    context.dataset.data.reduce(
                                        (sum, value) =>
                                            sum + Number(value),
                                        0
                                    );

                                const value = context.parsed;

                                const percentage =
                                    total > 0
                                        ? ((value / total) * 100).toFixed(1)
                                        : 0;

                                return (
                                    " " +
                                    context.label +
                                    ": " +
                                    value +
                                    " (" +
                                    percentage +
                                    "%)"
                                );
                            }
                        }
                    }
                }
            }
        });
    };


    /* =========================================================
       Source Distribution Chart
       ========================================================= */

    window.createSourceChart = function (
        canvasId = "sourceDistributionChart",
        labels = [
            "SIEM",
            "Network",
            "Authentication",
            "Palo Alto",
            "Threat Intel"
        ],
        values = [
            124,
            89,
            73,
            61,
            42
        ]
    ) {

        const canvas = getCanvas(canvasId);

        if (!canvas) {
            return null;
        }

        destroyExistingChart(canvas);

        const ctx = canvas.getContext("2d");

        return new Chart(ctx, {

            type: "bar",

            data: {

                labels: labels,

                datasets: [
                    {
                        label: "Simulated Events",

                        data: values,

                        backgroundColor: "#2563eb",

                        borderColor: "#3b82f6",

                        borderWidth: 1,

                        borderRadius: 4,

                        maxBarThickness: 36
                    }
                ]
            },

            options: {

                responsive: true,

                maintainAspectRatio: false,

                plugins: {

                    legend: {
                        display: false
                    }
                },

                scales: {

                    x: {

                        grid: {
                            display: false
                        },

                        ticks: {
                            color: "#64748b"
                        }
                    },

                    y: {

                        beginAtZero: true,

                        grid: {
                            color: "rgba(51, 65, 85, 0.35)"
                        },

                        ticks: {
                            color: "#64748b"
                        }
                    }
                }
            }
        });
    };


    /* =========================================================
       Investigation Workload Chart
       ========================================================= */

    window.createInvestigationWorkloadChart = function (
        canvasId = "investigationWorkloadChart"
    ) {

        const canvas = getCanvas(canvasId);

        if (!canvas) {
            return null;
        }

        destroyExistingChart(canvas);

        const ctx = canvas.getContext("2d");

        return new Chart(ctx, {

            type: "bar",

            data: {

                labels: [
                    "Analyst A",
                    "Analyst B",
                    "Analyst C",
                    "Analyst D",
                    "Unassigned"
                ],

                datasets: [
                    {
                        label: "Active Investigations",

                        data: [
                            6,
                            4,
                            8,
                            3,
                            2
                        ],

                        backgroundColor: "#0891b2",

                        borderRadius: 4,

                        maxBarThickness: 32
                    }
                ]
            },

            options: {

                responsive: true,

                maintainAspectRatio: false,

                plugins: {

                    legend: {
                        display: false
                    }
                },

                scales: {

                    x: {
                        grid: {
                            display: false
                        },

                        ticks: {
                            color: "#64748b"
                        }
                    },

                    y: {

                        beginAtZero: true,

                        ticks: {
                            precision: 0,
                            color: "#64748b"
                        },

                        grid: {
                            color: "rgba(51, 65, 85, 0.35)"
                        }
                    }
                }
            }
        });
    };


    /* =========================================================
       MITRE Tactic Distribution
       ========================================================= */

    window.createMitreTacticChart = function (
        canvasId = "mitreTacticChart",
        labels = [
            "Initial Access",
            "Execution",
            "Persistence",
            "Credential Access",
            "Discovery",
            "Command & Control"
        ],
        values = [
            12,
            18,
            9,
            14,
            21,
            11
        ]
    ) {

        const canvas = getCanvas(canvasId);

        if (!canvas) {
            return null;
        }

        destroyExistingChart(canvas);

        const ctx = canvas.getContext("2d");

        return new Chart(ctx, {

            type: "bar",

            data: {

                labels: labels,

                datasets: [
                    {
                        label: "Mapped Techniques",

                        data: values,

                        backgroundColor: "#06b6d4",

                        borderColor: "#22d3ee",

                        borderWidth: 1,

                        borderRadius: 4,

                        maxBarThickness: 30
                    }
                ]
            },

            options: {

                indexAxis: "y",

                responsive: true,

                maintainAspectRatio: false,

                plugins: {

                    legend: {
                        display: false
                    }
                },

                scales: {

                    x: {

                        beginAtZero: true,

                        ticks: {
                            precision: 0,
                            color: "#64748b"
                        },

                        grid: {
                            color: "rgba(51, 65, 85, 0.35)"
                        }
                    },

                    y: {

                        grid: {
                            display: false
                        },

                        ticks: {
                            color: "#94a3b8"
                        }
                    }
                }
            }
        });
    };


    /* =========================================================
       Risk Trend Chart
       ========================================================= */

    window.createRiskTrendChart = function (
        canvasId = "riskTrendChart"
    ) {

        const canvas = getCanvas(canvasId);

        if (!canvas) {
            return null;
        }

        destroyExistingChart(canvas);

        const ctx = canvas.getContext("2d");

        return new Chart(ctx, {

            type: "line",

            data: {

                labels: [
                    "Mon",
                    "Tue",
                    "Wed",
                    "Thu",
                    "Fri",
                    "Sat",
                    "Sun"
                ],

                datasets: [
                    {
                        label: "Average Risk",

                        data: [
                            54,
                            61,
                            58,
                            67,
                            72,
                            69,
                            76
                        ],

                        borderColor: "#f59e0b",

                        backgroundColor:
                            "rgba(245, 158, 11, 0.08)",

                        borderWidth: 2,

                        pointRadius: 3,

                        tension: 0.35,

                        fill: true
                    }
                ]
            },

            options: {

                responsive: true,

                maintainAspectRatio: false,

                plugins: {

                    legend: {
                        display: false
                    }
                },

                scales: {

                    x: {

                        grid: {
                            display: false
                        },

                        ticks: {
                            color: "#64748b"
                        }
                    },

                    y: {

                        min: 0,

                        max: 100,

                        grid: {
                            color: "rgba(51, 65, 85, 0.35)"
                        },

                        ticks: {
                            color: "#64748b"
                        }
                    }
                }
            }
        });
    };


    /* =========================================================
       Automatic Dashboard Chart Initialization
       ========================================================= */

    function initializeCharts() {

        createAlertVolumeChart();

        createSeverityChart();

        createSourceChart();

        createInvestigationWorkloadChart();

        createMitreTacticChart();

        createRiskTrendChart();
    }


    /*
     * Wait until the page has loaded.
     */
    document.addEventListener(
        "DOMContentLoaded",
        initializeCharts
    );


    /* =========================================================
       Chart Resize Helper
       ========================================================= */

    window.resizeARESCharts = function () {

        const charts = Chart.instances;

        Object.values(charts).forEach(function (chart) {

            if (chart && typeof chart.resize === "function") {
                chart.resize();
            }

        });
    };


    /* =========================================================
       Demo Chart Refresh
       ========================================================= */

    window.refreshARESCharts = function () {

        const charts = Chart.instances;

        Object.values(charts).forEach(function (chart) {

            if (!chart) {
                return;
            }

            chart.update("active");

        });

    };


    /* =========================================================
       Demo Notice
       ========================================================= */

    console.info(
        "ARES charts loaded — DEMO ENVIRONMENT. All chart data is simulated."
    );

})();