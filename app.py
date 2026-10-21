"""Small offline study-buddy prototype.

This file is deliberately simple. It is our learning version before we add
Gemini, accounts, and a database.
"""

import tkinter as tk
from tkinter import ttk


APP_TITLE = "Intel Study Buddy"


def offline_answer(question: str, mode: str) -> str:
    """Return a local response so the prototype works without internet."""
    question = question.strip()

    if not question:
        return "Type a question first."

    if mode == "Teacher":
        return (
            "Teacher workspace\n\n"
            f"You wrote: {question}\n\n"
            "Try turning this into an assignment by adding a clear goal, "
            "instructions, and a way to check the student's answer."
        )

    return (
        "Student workspace\n\n"
        f"You asked: {question}\n\n"
        "Study suggestion: explain what you already understand, identify "
        "one confusing part, and practise with a small example."
    )


class StudyBuddyApp:
    """Create the window and respond to the user's actions."""
    def __init__(self, root: tk.Tk):
        self.root = root
        self.mode = tk.StringVar(value="Student")
        self._build_window()

    def _build_window(self) -> None:
        """Create the visible controls in the window."""
        self.root.title(APP_TITLE)
        self.root.geometry("700x500")

        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            main_frame,
            text=APP_TITLE,
            font=("Helvetica", 22, "bold"),
        ).pack(anchor=tk.W, pady=(0, 15))

        ttk.Label(main_frame, text="Choose a workspace:").pack(anchor=tk.W)
        mode_frame = ttk.Frame(main_frame)
        mode_frame.pack(anchor=tk.W, pady=(5, 15))
        ttk.Radiobutton(
            mode_frame,
            text="Student",
            variable=self.mode,
            value="Student",
        ).pack(side=tk.LEFT, padx=(0, 15))
        ttk.Radiobutton(
            mode_frame,
            text="Teacher",
            variable=self.mode,
            value="Teacher",
        ).pack(side=tk.LEFT)

        ttk.Label(main_frame, text="What would you like help with?").pack(anchor=tk.W)
        self.question_box = tk.Text(main_frame, height=6, wrap=tk.WORD)
        self.question_box.pack(fill=tk.X, pady=(5, 10))

        ttk.Button(
            main_frame,
            text="Ask Study Buddy",
            command=self._ask_study_buddy,
        ).pack(anchor=tk.W)

        ttk.Label(main_frame, text="Response:").pack(anchor=tk.W, pady=(20, 5))
        self.response_box = tk.Text(main_frame, wrap=tk.WORD, state=tk.DISABLED)
        self.response_box.pack(fill=tk.BOTH, expand=True)

    def _ask_study_buddy(self) -> None:
        """Handle the button click and display the offline response."""
        question = self.question_box.get("1.0", tk.END)
        answer = offline_answer(question, self.mode.get())

        self.response_box.config(state=tk.NORMAL)
        self.response_box.delete("1.0", tk.END)
        self.response_box.insert("1.0", answer)
        self.response_box.config(state=tk.DISABLED)


def main() -> None:
    """Start Tkinter's event loop."""
    root = tk.Tk()
    StudyBuddyApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
