@echo off
REM ============================================================
REM  run_ablation.bat — WAF 7-way Ablation Harness (Windows)
REM
REM  Mirrors waf2/rag/scripts/run_ablation.sh for collaborators on
REM  Windows who don't have WSL/Git Bash. Runs 7 ablations end-to-end
REM  and appends one summary row per ablation to index.tsv.
REM
REM  Prerequisites:
REM    1. Ollama running on localhost:11434 with the model pulled
REM    2. WAF2 docker-compose stack up (port 8081)
REM    3. mcp-hub running on port 4000 (node mcp-hub\src\utils\cli.js)
REM    4. Node.js 18+, Python 3.10+, curl.exe (bundled with Win10+)
REM
REM  Usage (from repo root):
REM    waf2\rag\scripts\run_ablation.bat [model-tag]
REM
REM  Example:
REM    waf2\rag\scripts\run_ablation.bat qwen3-1_5b
REM
REM  Output:
REM    waf2\rag\eval\runs\<YYYY-MM-DD>-ablation-7way-<model-tag>\
REM      ├── index.tsv          (8 fields x 7 rows)
REM      ├── 1-waf1-only\ ... 7-full-no-react\
REM ============================================================

setlocal enabledelayedexpansion

REM -------- UTF-8 console (required for Chinese Windows / code page 936) --------
chcp 65001 >nul 2>&1
set "PYTHONUTF8=1"

REM -------- args --------
set "MODEL=%~1"
if "%MODEL%"=="" set "MODEL=qwen3-1_5b"

REM -------- date tag (YYYY-MM-DD) — PowerShell for Win10/11 compatibility --------
for /f %%I in ('powershell -NoProfile -Command "Get-Date -Format yyyy-MM-dd"') do set "DATE_TAG=%%I"

REM -------- paths --------
set "ROOT=waf2\rag\eval\runs\%DATE_TAG%-ablation-7way-%MODEL%"
set "INDEX=%ROOT%\index.tsv"
set "COOKIES=%ROOT%\cookies.txt"
set "ATTACKS=waf2\rag\eval\m-bench-core\attacks.jsonl"
set "BENIGNS_SRC=waf2\rag\eval\m-bench-core\benign.jsonl"
set "BENIGNS=%ROOT%\benign.jsonl"
set "DS=%ROOT%\_dataset"

set "MCP_HUB=http://localhost:4000"
set "WAF2=http://localhost:8081"
set "SCENARIOS=waf2\rag\eval\scenario-playbook\scenarios.jsonl"

echo.
echo === WAF Ablation Harness (Windows) — model=%MODEL% ===
echo Output: %ROOT%
echo.

if not exist "%ATTACKS%" (
  echo ERROR: attacks file not found: %ATTACKS%
  exit /b 2
)
if not exist "%BENIGNS_SRC%" (
  echo ERROR: benigns file not found: %BENIGNS_SRC%
  exit /b 2
)

if not exist "%ROOT%" mkdir "%ROOT%"
if not exist "%DS%"   mkdir "%DS%"

REM -------- pre-flight: services --------
curl.exe -fsS --max-time 3 "%MCP_HUB%/auth/login" -X POST -H "Content-Type: application/json" -d "{\"username\":\"admin\",\"password\":\"guardrails\"}" -c "%COOKIES%" >nul 2>&1
if errorlevel 1 (
  echo ERROR: mcp-hub login failed at %MCP_HUB%. Make sure mcp-hub is running.
  exit /b 3
)
curl.exe -fsS --max-time 3 "%WAF2%/waf2/config" >nul 2>&1
if errorlevel 1 (
  echo ERROR: WAF2 not reachable at %WAF2%. Make sure docker-compose stack is up.
  exit /b 3
)
echo [pre-flight] mcp-hub + WAF2 reachable, cookies stored in %COOKIES%

REM -------- benign sampling (equal-count, seeded) --------
python -c "import random,sys; random.seed(42); rows=[l for l in open(r'%BENIGNS_SRC%',encoding='utf-8') if l.strip()]; atk=sum(1 for l in open(r'%ATTACKS%',encoding='utf-8') if l.strip()); n=min(atk,len(rows)); picked=random.sample(rows,n); open(r'%BENIGNS%','w',encoding='utf-8').writelines(picked); print(f'[sample] {n}/{len(rows)} benigns -> ' + r'%BENIGNS%')"
if errorlevel 1 (
  echo ERROR: benign sampling failed.
  exit /b 3
)

REM -------- prepare dataset dir (merge expects attacks.jsonl + benign.jsonl) --------
copy /Y "%ATTACKS%" "%DS%\attacks.jsonl" >nul
copy /Y "%BENIGNS%" "%DS%\benign.jsonl"  >nul

REM ============================================================
REM  Ablation 1 — WAF1-only
REM ============================================================
set "OUT=%ROOT%\1-waf1-only"
if not exist "%OUT%" mkdir "%OUT%"
echo.
echo === Ablation 1: WAF1-only ===

curl.exe -fsS -b "%COOKIES%" -X POST -H "Content-Type: application/json" -d "{\"callChainEnabled\":true,\"dynamicPolicyEnabled\":true,\"rbacArgsEnabled\":true}" "%MCP_HUB%/api/config/waf1" >nul

node mcp-hub\scripts\run_waf1_on_mbench.mjs --jsonl "%ATTACKS%" --variant both --out-dir "%OUT%" || goto :fail
node mcp-hub\scripts\run_waf1_on_mbench.mjs --jsonl "%BENIGNS%" --variant both --out-dir "%OUT%" || goto :fail

python waf2\rag\scripts\merge_mbench_layers.py --cases-dir "%OUT%" --dataset-dir "%DS%" --out-dir "%OUT%" --skip-waf2 --ablation-label "WAF1-only" || goto :fail
python waf2\rag\scripts\report_mbench.py --merged "%OUT%\cases-mbench-merged.jsonl" --out "%OUT%\dual-layer-mbench-report.md" --ablation-label "WAF1-only" --append-to "%INDEX%" || goto :fail

node mcp-hub\scripts\run_waf1_on_scenario_playbook.mjs --jsonl "%SCENARIOS%" --out-dir "%OUT%" || goto :fail
python -c "open(r'%OUT%\cases-scenario-playbook-waf2.jsonl','w').close()"
python waf2\rag\scripts\report_scenario_playbook.py --waf1-cases "%OUT%\cases-scenario-playbook-waf1-full.jsonl" --waf2-cases "%OUT%\cases-scenario-playbook-waf2.jsonl" --out "%OUT%\scenario-playbook-summary.md" || goto :fail

REM ============================================================
REM  Ablation 2 — WAF2-only
REM ============================================================
set "OUT=%ROOT%\2-waf2-only"
if not exist "%OUT%" mkdir "%OUT%"
echo.
echo === Ablation 2: WAF2-only ===

curl.exe -fsS -X POST -H "Content-Type: application/json" -d "{\"rag_enabled\":true,\"react_routing_enabled\":true,\"eval_mode\":true,\"eval_fail_closed\":false}" "%WAF2%/waf2/config" >nul

python waf2\rag\scripts\run_waf2_on_mbench.py --waf2 "%WAF2%" --jsonl "%ATTACKS%" --rag-mode on --react-mode on --out-dir "%OUT%" || goto :fail
python waf2\rag\scripts\run_waf2_on_mbench.py --waf2 "%WAF2%" --jsonl "%BENIGNS%" --rag-mode on --react-mode on --out-dir "%OUT%" || goto :fail

python waf2\rag\scripts\merge_mbench_layers.py --cases-dir "%OUT%" --dataset-dir "%DS%" --out-dir "%OUT%" --skip-waf1 --ablation-label "WAF2-only" || goto :fail
python waf2\rag\scripts\report_mbench.py --merged "%OUT%\cases-mbench-merged.jsonl" --out "%OUT%\dual-layer-mbench-report.md" --ablation-label "WAF2-only" --append-to "%INDEX%" || goto :fail

python -c "open(r'%OUT%\cases-scenario-playbook-waf1-full.jsonl','w').close()"
python waf2\rag\scripts\run_waf2_on_scenario_playbook.py --waf2 "%WAF2%" --jsonl "%SCENARIOS%" --out-dir "%OUT%" || goto :fail
python waf2\rag\scripts\report_scenario_playbook.py --waf1-cases "%OUT%\cases-scenario-playbook-waf1-full.jsonl" --waf2-cases "%OUT%\cases-scenario-playbook-waf2.jsonl" --out "%OUT%\scenario-playbook-summary.md" || goto :fail

REM ============================================================
REM  Ablation 3 — Full (WAF1 + WAF2, rag=on react=on)
REM ============================================================
set "OUT=%ROOT%\3-full"
if not exist "%OUT%" mkdir "%OUT%"
echo.
echo === Ablation 3: Full ===

curl.exe -fsS -b "%COOKIES%" -X POST -H "Content-Type: application/json" -d "{\"callChainEnabled\":true,\"dynamicPolicyEnabled\":true,\"rbacArgsEnabled\":true}" "%MCP_HUB%/api/config/waf1" >nul
curl.exe -fsS -X POST -H "Content-Type: application/json" -d "{\"rag_enabled\":true,\"react_routing_enabled\":true,\"eval_mode\":true,\"eval_fail_closed\":false}" "%WAF2%/waf2/config" >nul

node mcp-hub\scripts\run_waf1_on_mbench.mjs --jsonl "%ATTACKS%" --variant both --out-dir "%OUT%" || goto :fail
node mcp-hub\scripts\run_waf1_on_mbench.mjs --jsonl "%BENIGNS%" --variant both --out-dir "%OUT%" || goto :fail
python waf2\rag\scripts\run_waf2_on_mbench.py --waf2 "%WAF2%" --jsonl "%ATTACKS%" --rag-mode on --react-mode on --out-dir "%OUT%" || goto :fail
python waf2\rag\scripts\run_waf2_on_mbench.py --waf2 "%WAF2%" --jsonl "%BENIGNS%" --rag-mode on --react-mode on --out-dir "%OUT%" || goto :fail

python waf2\rag\scripts\merge_mbench_layers.py --cases-dir "%OUT%" --dataset-dir "%DS%" --out-dir "%OUT%" --ablation-label "Full" || goto :fail
python waf2\rag\scripts\report_mbench.py --merged "%OUT%\cases-mbench-merged.jsonl" --out "%OUT%\dual-layer-mbench-report.md" --ablation-label "Full" --append-to "%INDEX%" || goto :fail

node mcp-hub\scripts\run_waf1_on_scenario_playbook.mjs --jsonl "%SCENARIOS%" --out-dir "%OUT%" || goto :fail
python waf2\rag\scripts\run_waf2_on_scenario_playbook.py --waf2 "%WAF2%" --jsonl "%SCENARIOS%" --out-dir "%OUT%" || goto :fail
python waf2\rag\scripts\report_scenario_playbook.py --waf1-cases "%OUT%\cases-scenario-playbook-waf1-full.jsonl" --waf2-cases "%OUT%\cases-scenario-playbook-waf2.jsonl" --out "%OUT%\scenario-playbook-summary.md" || goto :fail

REM ============================================================
REM  Ablation 4 — Full no-chain  (reuse ablation 3's WAF2)
REM ============================================================
set "OUT=%ROOT%\4-full-no-chain"
if not exist "%OUT%" mkdir "%OUT%"
echo.
echo === Ablation 4: Full no-chain ===

curl.exe -fsS -b "%COOKIES%" -X POST -H "Content-Type: application/json" -d "{\"callChainEnabled\":false,\"dynamicPolicyEnabled\":true,\"rbacArgsEnabled\":true}" "%MCP_HUB%/api/config/waf1" >nul

node mcp-hub\scripts\run_waf1_on_mbench.mjs --jsonl "%ATTACKS%" --variant both --out-dir "%OUT%" --no-call-chain || goto :fail
node mcp-hub\scripts\run_waf1_on_mbench.mjs --jsonl "%BENIGNS%" --variant both --out-dir "%OUT%" --no-call-chain || goto :fail
copy /Y "%ROOT%\3-full\cases-mbench-attacks-rag-on.jsonl" "%OUT%\" >nul
copy /Y "%ROOT%\3-full\cases-mbench-benign-rag-on.jsonl"  "%OUT%\" >nul

python waf2\rag\scripts\merge_mbench_layers.py --cases-dir "%OUT%" --dataset-dir "%DS%" --out-dir "%OUT%" --ablation-label "Full no-chain" || goto :fail
python waf2\rag\scripts\report_mbench.py --merged "%OUT%\cases-mbench-merged.jsonl" --out "%OUT%\dual-layer-mbench-report.md" --ablation-label "Full no-chain" --append-to "%INDEX%" || goto :fail

node mcp-hub\scripts\run_waf1_on_scenario_playbook.mjs --jsonl "%SCENARIOS%" --out-dir "%OUT%" || goto :fail
python waf2\rag\scripts\run_waf2_on_scenario_playbook.py --waf2 "%WAF2%" --jsonl "%SCENARIOS%" --out-dir "%OUT%" || goto :fail
python waf2\rag\scripts\report_scenario_playbook.py --waf1-cases "%OUT%\cases-scenario-playbook-waf1-full.jsonl" --waf2-cases "%OUT%\cases-scenario-playbook-waf2.jsonl" --out "%OUT%\scenario-playbook-summary.md" || goto :fail

REM ============================================================
REM  Ablation 5 — Full no-dynSQL  (reuse ablation 3's WAF2)
REM ============================================================
set "OUT=%ROOT%\5-full-no-dynsql"
if not exist "%OUT%" mkdir "%OUT%"
echo.
echo === Ablation 5: Full no-dynSQL ===

curl.exe -fsS -b "%COOKIES%" -X POST -H "Content-Type: application/json" -d "{\"callChainEnabled\":true,\"dynamicPolicyEnabled\":false,\"rbacArgsEnabled\":true}" "%MCP_HUB%/api/config/waf1" >nul

node mcp-hub\scripts\run_waf1_on_mbench.mjs --jsonl "%ATTACKS%" --variant both --out-dir "%OUT%" --no-dyn-policy || goto :fail
node mcp-hub\scripts\run_waf1_on_mbench.mjs --jsonl "%BENIGNS%" --variant both --out-dir "%OUT%" --no-dyn-policy || goto :fail
copy /Y "%ROOT%\3-full\cases-mbench-attacks-rag-on.jsonl" "%OUT%\" >nul
copy /Y "%ROOT%\3-full\cases-mbench-benign-rag-on.jsonl"  "%OUT%\" >nul

python waf2\rag\scripts\merge_mbench_layers.py --cases-dir "%OUT%" --dataset-dir "%DS%" --out-dir "%OUT%" --ablation-label "Full no-dynSQL" || goto :fail
python waf2\rag\scripts\report_mbench.py --merged "%OUT%\cases-mbench-merged.jsonl" --out "%OUT%\dual-layer-mbench-report.md" --ablation-label "Full no-dynSQL" --append-to "%INDEX%" || goto :fail

node mcp-hub\scripts\run_waf1_on_scenario_playbook.mjs --jsonl "%SCENARIOS%" --out-dir "%OUT%" || goto :fail
python waf2\rag\scripts\run_waf2_on_scenario_playbook.py --waf2 "%WAF2%" --jsonl "%SCENARIOS%" --out-dir "%OUT%" || goto :fail
python waf2\rag\scripts\report_scenario_playbook.py --waf1-cases "%OUT%\cases-scenario-playbook-waf1-full.jsonl" --waf2-cases "%OUT%\cases-scenario-playbook-waf2.jsonl" --out "%OUT%\scenario-playbook-summary.md" || goto :fail

REM ============================================================
REM  Ablation 6 — Full no-RAG  (WAF2 rag_enabled=false; reuse WAF1 from 3)
REM ============================================================
set "OUT=%ROOT%\6-full-no-rag"
if not exist "%OUT%" mkdir "%OUT%"
echo.
echo === Ablation 6: Full no-RAG ===

curl.exe -fsS -X POST -H "Content-Type: application/json" -d "{\"rag_enabled\":false,\"react_routing_enabled\":true,\"eval_mode\":true,\"eval_fail_closed\":false}" "%WAF2%/waf2/config" >nul

python waf2\rag\scripts\run_waf2_on_mbench.py --waf2 "%WAF2%" --jsonl "%ATTACKS%" --rag-mode off --react-mode on --out-dir "%OUT%" || goto :fail
python waf2\rag\scripts\run_waf2_on_mbench.py --waf2 "%WAF2%" --jsonl "%BENIGNS%" --rag-mode off --react-mode on --out-dir "%OUT%" || goto :fail

REM Move rag-off files into the rag-on slot so merge's 4-layer join finds WAF2 data.
if exist "%OUT%\cases-mbench-attacks-rag-off.jsonl" move /Y "%OUT%\cases-mbench-attacks-rag-off.jsonl" "%OUT%\cases-mbench-attacks-rag-on.jsonl" >nul
if exist "%OUT%\cases-mbench-benign-rag-off.jsonl"  move /Y "%OUT%\cases-mbench-benign-rag-off.jsonl"  "%OUT%\cases-mbench-benign-rag-on.jsonl"  >nul
copy /Y "%ROOT%\3-full\cases-mbench-attacks-waf1-strict.jsonl" "%OUT%\" >nul
copy /Y "%ROOT%\3-full\cases-mbench-attacks-waf1-full.jsonl"   "%OUT%\" >nul
copy /Y "%ROOT%\3-full\cases-mbench-benign-waf1-strict.jsonl"  "%OUT%\" >nul
copy /Y "%ROOT%\3-full\cases-mbench-benign-waf1-full.jsonl"    "%OUT%\" >nul

python waf2\rag\scripts\merge_mbench_layers.py --cases-dir "%OUT%" --dataset-dir "%DS%" --out-dir "%OUT%" --ablation-label "Full no-RAG" || goto :fail
python waf2\rag\scripts\report_mbench.py --merged "%OUT%\cases-mbench-merged.jsonl" --out "%OUT%\dual-layer-mbench-report.md" --ablation-label "Full no-RAG" --append-to "%INDEX%" || goto :fail

node mcp-hub\scripts\run_waf1_on_scenario_playbook.mjs --jsonl "%SCENARIOS%" --out-dir "%OUT%" || goto :fail
python waf2\rag\scripts\run_waf2_on_scenario_playbook.py --waf2 "%WAF2%" --jsonl "%SCENARIOS%" --out-dir "%OUT%" || goto :fail
python waf2\rag\scripts\report_scenario_playbook.py --waf1-cases "%OUT%\cases-scenario-playbook-waf1-full.jsonl" --waf2-cases "%OUT%\cases-scenario-playbook-waf2.jsonl" --out "%OUT%\scenario-playbook-summary.md" || goto :fail

REM ============================================================
REM  Ablation 7 — Full no-ReAct  (WAF2 react=false; reuse WAF1 from 3)
REM ============================================================
set "OUT=%ROOT%\7-full-no-react"
if not exist "%OUT%" mkdir "%OUT%"
echo.
echo === Ablation 7: Full no-ReAct ===

curl.exe -fsS -X POST -H "Content-Type: application/json" -d "{\"rag_enabled\":true,\"react_routing_enabled\":false,\"eval_mode\":true,\"eval_fail_closed\":false}" "%WAF2%/waf2/config" >nul

python waf2\rag\scripts\run_waf2_on_mbench.py --waf2 "%WAF2%" --jsonl "%ATTACKS%" --rag-mode on --react-mode off --out-dir "%OUT%" || goto :fail
python waf2\rag\scripts\run_waf2_on_mbench.py --waf2 "%WAF2%" --jsonl "%BENIGNS%" --rag-mode on --react-mode off --out-dir "%OUT%" || goto :fail

REM Move rag-on-react-off files into the rag-on slot.
if exist "%OUT%\cases-mbench-attacks-rag-on-react-off.jsonl" move /Y "%OUT%\cases-mbench-attacks-rag-on-react-off.jsonl" "%OUT%\cases-mbench-attacks-rag-on.jsonl" >nul
if exist "%OUT%\cases-mbench-benign-rag-on-react-off.jsonl"  move /Y "%OUT%\cases-mbench-benign-rag-on-react-off.jsonl"  "%OUT%\cases-mbench-benign-rag-on.jsonl"  >nul
copy /Y "%ROOT%\3-full\cases-mbench-attacks-waf1-strict.jsonl" "%OUT%\" >nul
copy /Y "%ROOT%\3-full\cases-mbench-attacks-waf1-full.jsonl"   "%OUT%\" >nul
copy /Y "%ROOT%\3-full\cases-mbench-benign-waf1-strict.jsonl"  "%OUT%\" >nul
copy /Y "%ROOT%\3-full\cases-mbench-benign-waf1-full.jsonl"    "%OUT%\" >nul

python waf2\rag\scripts\merge_mbench_layers.py --cases-dir "%OUT%" --dataset-dir "%DS%" --out-dir "%OUT%" --ablation-label "Full no-ReAct" || goto :fail
python waf2\rag\scripts\report_mbench.py --merged "%OUT%\cases-mbench-merged.jsonl" --out "%OUT%\dual-layer-mbench-report.md" --ablation-label "Full no-ReAct" --append-to "%INDEX%" || goto :fail

node mcp-hub\scripts\run_waf1_on_scenario_playbook.mjs --jsonl "%SCENARIOS%" --out-dir "%OUT%" || goto :fail
python waf2\rag\scripts\run_waf2_on_scenario_playbook.py --waf2 "%WAF2%" --jsonl "%SCENARIOS%" --out-dir "%OUT%" || goto :fail
python waf2\rag\scripts\report_scenario_playbook.py --waf1-cases "%OUT%\cases-scenario-playbook-waf1-full.jsonl" --waf2-cases "%OUT%\cases-scenario-playbook-waf2.jsonl" --out "%OUT%\scenario-playbook-summary.md" || goto :fail

REM ============================================================
REM  Done
REM ============================================================
echo.
echo === All 7 ablations complete ===
echo Index TSV: %INDEX%
echo.
type "%INDEX%"
echo.
echo Package the run dir for upload:
echo   powershell Compress-Archive -Path "%ROOT%" -DestinationPath "ablation-%MODEL%.zip"
exit /b 0

:fail
echo.
echo *** ABLATION FAILED *** (exit code %errorlevel%)
echo Inspect the output above. Partial results may still be in %ROOT%
exit /b 1
