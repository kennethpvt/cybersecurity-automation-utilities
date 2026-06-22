import re

def check_password_strength(password):
    score = 0
    feedback = []

    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Password is too short (Minimum 8 characters required, 12+ recommended).")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Missing at least one uppercase letter (A-Z).")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Missing at least one lowercase letter (a-z).")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Missing at least one numerical digit (0-9).")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>_+-]", password):
        score += 1
    else:
        feedback.append("Missing at least one special character (e.g., !, @, #, $, %).")

    if score >= 6:
        rating = "Very Strong"
    elif score in [4, 5]:
        rating = "Strong / Acceptable"
    elif score == 3:
        rating = "Moderate"
    else:
        rating = "Weak"

    return rating, score, feedback

def main():
    print("=" * 50)
    print("         Enterprise Password Strength Evaluator       ")
    print("=" * 50)
    
    user_password = input("Enter a password to evaluate: ").strip()
    
    if not user_password:
        print("[!] Input cannot be empty.")
        return

    rating, score, remediation_steps = check_password_strength(user_password)

    print("\n" + "-" * 40)
    print(f"Strength Rating:  {rating}")
    print(f"Raw Matrix Score: {score}/6")
    print("-" * 40)

    if remediation_steps:
        print("\nSuggestions to improve security:")
        for step in remediation_steps:
            print(f" * {step}")
    else:
        print("\n[+] Excellent! This password meets or exceeds enterprise complexity standards.")
    print("-" * 40)

if __name__ == "__main__":
    main()
