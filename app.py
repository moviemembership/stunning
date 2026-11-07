                    # Search:
                    # Your verification code
                    # Kod pengesahan anda
                    code, error = (
                        get_mantapnet_verification_code(
                            email_value
                        )
                    )

                elif not password_value:
                    error = (
                        "Please enter both email and password."
                    )

                else:
                    try:
                        code, error = get_verification_code(
                            email_value,
                            password_value
                        )

                    except Exception as exc:
                        app.logger.exception(
                            "Verification code error: %s",
                            exc
                        )

                        error = (
                            "System is busy or timed out. "
                            "Please try again."
                        )

            # =============================================
            # HOUSEHOLD CODE
            # =============================================
            elif selected == "household":

                if not email_value:
                    error = "Please enter the account email."

                elif is_mantapnet_email:
                    # Use your existing Mantapnet household
                    # mailbox method.
                    try:
                        code, error = household_code_from_mailbox(
                            email_value
                        )

                    except NameError:
                        # Use this only if you have not yet
                        # extracted /household-code into a helper.
                        error = (
                            "The Mantapnet household helper has "
                            "not been connected yet."
                        )

                else:
                    # Outlook/Hotmail household method.
                    try:
                        code, error = (
                            get_outlook_household_code(
                                email_value
                            )
                        )

                    except Exception as exc:
                        app.logger.exception(
                            "Household code error: %s",
                            exc
                        )

                        error = (
                            "System is busy or timed out. "
                            "Please try again."
                        )

    return render_template(
        "get_code.html",
        selected=selected,
        email=email_value,
        password=password_value,
        code=code,
        error=error
    )

# =========================================================
# SHORT CODE GUIDE PAGES
# =========================================================

@app.route("/video/<path:filename>")
def video_files(filename):
    return send_from_directory(
        "video",
        filename
    )


@app.route("/s")
def signin_guide():
    return render_template(
        "signin_guide.html"
    )


@app.route("/v")
def verification_guide():
    return render_template(
        "verification_guide.html"
    )

@app.route("/p")
def use_password_picture():
    return render_template("use_password.html")

# ---------------- MAIN ----------------
if __name__ == "__main__":
    app.run(debug=True)
