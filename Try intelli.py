import os
import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
from datetime import datetime, timezone, timedelta
import traceback
import csv
import hashlib
import base64
import secrets
import threading
import re
from typing import List, Dict, Any, Optional

# Import the dedicated AI module
from gemini_companion import GeminiCompanion

# --- UTILITIES (Mocked for context) ---

def _format_date_time_local(date_str: str, time_str: str) -> str:
    """Mock function to format date/time string."""
    try:
        return f"{date_str} @ {time_str}"
    except Exception:
        return "N/A"

# Mock Database for integration context
class MockDB:
    """A mock class to simulate the database operations."""
    def __init__(self):
        # Sample data mimicking syllabus items
        self._items = [
            {'id': 1, 'subject': 'Calculus I', 'type': 'Assignment', 'date': '2025-10-25', 'time': '17:00', 'details': 'Integrate the function 3x^2 + 2x.'},
            {'id': 2, 'subject': 'History 101', 'type': 'Exam', 'date': '2025-11-05', 'time': '10:00', 'details': 'Covers World War II and the Cold War eras.'},
            {'id': 3, 'subject': 'Python Programming', 'type': 'Project', 'date': '2025-11-15', 'time': '23:59', 'details': 'Build a Tkinter GUI application.'},
        ]

    def list_items(self) -> List[Dict[str, Any]]:
        """Returns the list of syllabus items."""
        return self._items

# --- MAIN APPLICATION ---

class IntelliApp:
    def __init__(self, master: tk.Tk):
        self.master = master
        master.title("Intelli-Study Planner")
        master.geometry("800x600")

        # Mock initialization of necessary components
        self.db = MockDB()
        self.current_user = "test_user"

        # Initialize the AI Companion CORE
        self.ai_companion = GeminiCompanion()

        self._create_main_ui()

    def _create_main_ui(self):
        """Creates a simplified main UI for context."""
        main_frame = ttk.Frame(self.master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="Syllabus Overview (Mock Data)", font=("Arial", 16, "bold")).pack(pady=10)
        
        # Display mock syllabus items
        list_frame = ttk.Frame(main_frame)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        syllabus_text = tk.Text(list_frame, height=10, wrap=tk.WORD, font=("Consolas", 10))
        syllabus_text.pack(fill=tk.BOTH, expand=True)
        
        context = self._get_syllabus_context()
        syllabus_text.insert(tk.END, context)
        syllabus_text.config(state=tk.DISABLED) # Make it read-only
        
        # AI Companion Button
        ttk.Button(main_frame, text="Launch AI Companion", command=self._show_ai_companion).pack(pady=20)


    def _get_syllabus_context(self) -> str:
        """
        Generates the syllabus context string passed to the AI.
        """
        items = self.db.list_items()
        ctx = "Current Syllabus/To-Do Items:\n"
        for item in items:
            date_time = _format_date_time_local(item['date'], item['time'])
            ctx += f"- {item['subject']} ({item['type']}): Due {date_time}. Details: {item['details']}\n"
        return ctx

    def _show_ai_companion(self):
        """
        Creates and displays the AI Companion interface.
        """
        ai_win = tk.Toplevel(self.master)
        ai_win.title("AI Study Companion (Gemini Core)")
        ai_win.geometry("500x500")
        ai_win.transient(self.master)

        ttk.Label(ai_win, text="Ask the AI for analysis or recommendations:", font=("Arial", 12)).pack(pady=10)

        # 1. User Input Area
        prompt_label = ttk.Label(ai_win, text="Your Question/Goal:")
        prompt_label.pack(padx=10, anchor='w')
        
        prompt_text = tk.Text(ai_win, height=5, wrap=tk.WORD)
        prompt_text.pack(fill=tk.X, padx=10, pady=5)
        
        # 2. Query Logic
        def _query():
            """Initiates the threaded AI query."""
            user_question = prompt_text.get("1.0", tk.END).strip()
            if not user_question:
                messagebox.showerror("Error", "Please enter a question for the AI.")
                return

            # Combine the current syllabus context with the user's specific question
            syllabus_context = self._get_syllabus_context()
            full_prompt = (
                f"Syllabus Context:\n{syllabus_context}\n\n"
                f"User's Question/Goal:\n{user_question}"
            )

            query_btn.config(text="Querying...", state="disabled")
            resp_text.delete("1.0", tk.END)
            resp_text.insert("1.0", "Analyzing data with Gemini... please wait.")

            # Start the AI query in a separate thread
            thread = threading.Thread(
                target=self.ai_companion.query, 
                args=(
                    full_prompt, 
                    lambda r: self.master.after(0, _handle_companion_response, r, query_btn), 
                    lambda e: self.master.after(0, _handle_companion_error, e, query_btn)
                ), 
                daemon=True
            )
            thread.start()
        
        def _handle_companion_response(response: str, btn: ttk.Button):
            """Handle successful AI companion response (runs in main thread)."""
            btn.config(text="Query", state="normal")
            resp_text.delete("1.0", tk.END)
            resp_text.insert("1.0", response)
        
        def _handle_companion_error(error_msg: str, btn: ttk.Button):
            """Handle AI companion error (runs in main thread)."""
            btn.config(text="Query", state="normal")
            resp_text.delete("1.0", tk.END)
            resp_text.insert("1.0", f"AI Error: {error_msg}")

        # 3. Query Button
        query_btn = ttk.Button(ai_win, text="Query", command=_query)
        query_btn.pack(pady=10)

        # 4. Response Area
        resp_label = ttk.Label(ai_win, text="AI Structured Analysis:")
        resp_label.pack(padx=10, anchor='w', pady=(10, 0))
        
        resp_text = tk.Text(ai_win, height=15, wrap=tk.WORD)
        resp_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)


# --- APPLICATION START ---
if __name__ == "__main__":
    # Ensure the companion module exists before running
    if not os.path.exists("gemini_companion.py"):
        print("FATAL ERROR: The 'gemini_companion.py' file is missing.")
        print("Please ensure both 'Intelli.py' and 'gemini_companion.py' are in the same directory.")
    else:
        root = tk.Tk()
        app = IntelliApp(root)
        root.mainloop()
