from fastapi import FastAPI, Request
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
import json
import uvicorn
import argparse

app = FastAPI(title="AXG Audit Webhook Lab")
console = Console()

@app.post("/webhook")
async def receive_audit_log(request: Request):
    """Receives the audit JSON payload and prints it beautifully."""
    try:
        data = await request.json()
        
        # Determine color based on decision
        decision = data.get("decision", "UNKNOWN")
        color = "green" if decision == "ALLOW" else "red" if decision == "BLOCK" else "yellow"
        
        # Format JSON for rich printing
        json_str = json.dumps(data, indent=2)
        syntax = Syntax(json_str, "json", theme="monokai", line_numbers=False)
        
        panel = Panel(
            syntax,
            title=f"[{color}]AXG Audit Received: {decision}[/]",
            subtitle=f"[dim]Execution ID: {data.get('execution_id', 'N/A')}[/]",
            border_style=color,
            expand=False
        )
        
        console.print(panel)
        return {"status": "received"}
        
    except Exception as e:
        console.print(f"[bold red]Error parsing webhook payload: {e}[/]")
        return {"status": "error"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the AXG Audit Webhook Listener")
    parser.add_argument("--port", type=int, default=9999, help="Port to run the listener on")
    args = parser.parse_args()
    
    console.print(f"[bold blue]🚀 Starting AXG Audit Webhook Lab on port {args.port}[/]")
    console.print("[dim]Waiting for POST requests on /webhook...[/]")
    uvicorn.run(app, host="0.0.0.0", port=args.port, log_level="error")
