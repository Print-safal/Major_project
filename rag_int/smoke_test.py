from rag_int.rag_llm_integration import review_code_with_rag

code = """
import sqlite3

def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    conn = sqlite3.connect("app.db")
    return conn.execute(query).fetchall()
"""

print("Running RAG + LLM smoke test...")

try:
    result = review_code_with_rag(code)

    print("\nSMOKE TEST RESULT:")
    print(result.model_dump_json(indent=2))

except Exception as e:
    print("\nSMOKE TEST FAILED:")
    print(type(e).__name__, str(e))