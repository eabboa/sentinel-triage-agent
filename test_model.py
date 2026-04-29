import os
from langchain_google_genai import ChatGoogleGenerativeAI
try:
    llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", max_retries=0)
    print("Calling model...")
    res = llm.invoke("hello")
    print(res)
except Exception as e:
    print(f"ERROR: {type(e)}")
    print(f"STRING: {str(e)}")
