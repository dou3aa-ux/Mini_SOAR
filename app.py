from flask import Flask, abort, render_template

from ids.database import get_alert_by_id, get_recent_alerts


app = Flask(__name__)


@app.route("/")
def dashboard():
    alerts = get_recent_alerts()

    stats = {
        "total": len(alerts),
        "high": sum(alert["severity"] == "high" for alert in alerts),
        "medium": sum(alert["severity"] == "medium" for alert in alerts),
    }

    return render_template(
        "dashboard.html",
        alerts=alerts,
        stats=stats,
    )

@app.route("/alerts/<int:alert_id>")
def alert_detail(alert_id):
    alert = get_alert_by_id(alert_id)

    if alert is None:
        abort(404)

    return render_template("alert_detail.html", alert=alert)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)