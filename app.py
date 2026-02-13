from flask import Flask, render_template, request
from analyzer import analyze_url, analyze_email, check_password_strength

app = Flask(__name__)

def get_risk_level(score):
    if score <= 30:
        return "Safe", "green"
    elif score <= 60:
        return "Suspicious", "orange"
    else:
        return "High Risk", "red"
@app.route("/", methods=["GET", "POST"])
def home():

    url_score = 0
    email_score = 0
    password_score = None
    url_reasons = []
    email_reasons = []

    if request.method == "POST":

        if request.form.get("url"):
            url_score, url_reasons = analyze_url(request.form["url"])

        if request.form.get("email"):
            email_score, email_reasons = analyze_email(request.form["email"])

        if request.form.get("password"):
            password_score = check_password_strength(request.form["password"])

    return render_template(
        "index.html",
        url_score=url_score,
        email_score=email_score,
        password_score=password_score,
        url_reasons=url_reasons,
        email_reasons=email_reasons
    )

if __name__ == "__main__":
    app.run(debug=True)
