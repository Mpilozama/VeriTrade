@echo off
echo Starting VeriTrade AI Backend...
call venv\Scripts\activate
uvicorn main:app --reload
pause