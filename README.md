# AI Code Reviewer

An AI-powered Python security code review system that combines Retrieval-Augmented Generation (RAG) with a Large Language Model (LLM) to identify common security vulnerabilities and provide explanations and remediation guidance.

## Project Architecture

```text
Major_project/
|-- backend/                 # Django REST API
|-- frontend/                # React + TypeScript + Vite
|-- rag/                     # RAG pipeline and security knowledge base
|-- rag_int/                 # RAG + LLM integration
|-- llm/                     # LLM evaluation and test datasets
|-- requirements.txt         # Python dependencies
`-- README.md