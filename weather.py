from typing import Any
import httpx
from mcp.server.fastmcp import FastMCP
import logging
import os
import pickle
import base64
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build 

mcp = FastMCP("weather")

alert_history = []

NWS_API_BASE = "https://api.weather.gov"
USER_AGENT = "weather-app/1.0"

def load_config():
	"""Load configuration from config.json file."""
	try:
		with open('config.json', 'r') as f:
			config = json.load(f)
			if 'email' not in config:
				raise ValueError("Email not found in config.json file")
			return config
	except FileNotFoundError:
		raise FileNotFoundError("Config file 'config.json' not found. Please create it with an 'email' field.")

# Gmail API
SCOPES = ['https://www.googleapis.com/auth/gmail.send']
CREDENTIALS_FILE = 'credentials.json'
TOKEN_FILE = 'token.json'

async def make_nws_request(url: str) -> dict[str, Any] | None:
	"""Make a request to the NWS API."""
	headers = {
		"User-Agent": USER_AGENT,
		"Accept": "application/geo+json"
	}
	async with httpx.AsyncClient() as client:
		try:
			response = await client.get(url, headers=headers, timeout=30.0)
			response.raise_for_status()
			return response.json()
		except Exception:
			return None

def format_alert(feature: dict) -> str:
	"""Format an alert feature into a readable string."""
	props = feature["properties"]
	return f"""
Event: {props.get('event', 'Unknown')}
Area: {props.get('areaDesc', 'Unknown')}
Severity: {props.get('severity', 'Unknown')}
Description: {props.get('description', 'No description available')}
Instructions: {props.get('instruction', 'No specific instructions provided')}
"""

def create_alert_summary(state: str, features: list) -> str:
	"""Create a short bullet point summary of alerts for tracking."""
	if not features:
		return f"- {state}: 0 alerts"
	
	alert_count = len(features)
	events = [feature["properties"].get("event", "Unknown") for feature in features]
	unique_events = list(set(events))
	
	# Keep only the most relevant event types for summary
	summary_events = unique_events[:2] 
	events_str = ", ".join(summary_events)
	
	return f"- {state}: {alert_count} alerts, {events_str}"

def get_gmail_service():
	"""Set up and return Gmail API service."""
	creds = None
	
	# Load existing token
	if os.path.exists(TOKEN_FILE):
		with open(TOKEN_FILE, 'rb') as token:
			creds = pickle.load(token)
	
	if not creds or not creds.valid:
		if creds and creds.expired and creds.refresh_token:
			creds.refresh(Request())
		else:
			if not os.path.exists(CREDENTIALS_FILE):
				raise FileNotFoundError(f"Gmail credentials file '{CREDENTIALS_FILE}' not found. Please download it from Google Cloud Console.")
			
			flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
			creds = flow.run_local_server(port=8080)
		
		# Save credentials for next run
		with open(TOKEN_FILE, 'wb') as token:
			pickle.dump(creds, token)
	
	return build('gmail', 'v1', credentials=creds)

def create_email_message(to_email: str, subject: str, body: str) -> dict:
	"""Create an email message."""
	message = MIMEMultipart()
	message['to'] = to_email
	message['subject'] = subject
	
	message.attach(MIMEText(body, 'plain'))
	
	raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')
	return {'raw': raw_message}

@mcp.tool()
async def get_alerts(state: str) -> str:
	"""Get weather alerts for a US state.

	Args:
		state: Two-letter US state code (e.g. CA, NY)
	"""
	logging.info("Getting alerts")
	url = f"{NWS_API_BASE}/alerts/active/area/{state}"
	data = await make_nws_request(url)

	if not data or "features" not in data:
		alert_summary = f"- {state}: Unable to fetch alerts"
		alert_history.append(alert_summary)
		return "Unable to fetch alerts or no alerts found."

	features = data["features"]
	alert_summary = create_alert_summary(state, features)
	alert_history.append(alert_summary)

	if not features:
		return "No active alerts for this state."

	alerts = [format_alert(feature) for feature in features]
	return "\n---\n".join(alerts)

@mcp.tool()
async def get_forecast(latitude: float, longitude: float) -> str:
	"""Get weather forecast for a location.

	Args: 
		latitude: Latitude of the location
		longitude: Longitude of the location
	"""
	# First get the forecast grid endpoint
	points_url = f"{NWS_API_BASE}/points/{latitude},{longitude}"
	points_data = await make_nws_request(points_url)

	if not points_data:
		return "Unable to fetch forecast data for this location."

	# Get the forecast URL from the points response
	forecast_url = points_data["properties"]["forecast"]
	forecast_data = await make_nws_request(forecast_url)

	if not forecast_data:
		return "Unable to fetch detailed forecast."

	# Format the periods into a readable forecast
	periods = forecast_data["properties"]["periods"]
	forecasts = []
	for period in periods[:5]:
		forecast = f"""
{period['name']}:
Temperature: {period['temperature']}°{period['temperatureUnit']}
Wind: {period['windSpeed']} {period['windDirection']}
Forecast: {period['detailedForecast']}
"""
		forecasts.append(forecast)
	return "\n---\n".join(forecasts)

@mcp.tool()
async def get_alert_history() -> str:
	"""Get the history of all weather alert requests and their results.
	
	Returns a bullet point list of locations where alerts were requested
	and a summary of the results.
	"""
	if not alert_history:
		return "No weather alert requests have been made yet."
	
	return "\n".join(alert_history)

@mcp.tool()
async def send_email(to_email: str, subject: str, body: str) -> str:
	"""Send an email using Gmail API.
	
	Args:
		to_email: Recipient email address
		subject: Email subject line  
		body: Email body content
	"""
	try:
		service = get_gmail_service()
		message = create_email_message(to_email, subject, body)
		
		result = service.users().messages().send(userId='me', body=message).execute()
		return f"Email sent successfully to {to_email}. Message ID: {result['id']}"
		
	except FileNotFoundError as e:
		return f"Error: {str(e)}"
	except Exception as e:
		return f"Failed to send email: {str(e)}"

@mcp.tool()
async def send_weather_summary(to_email: str = None) -> str:
	"""Send a summary of weather alert history via email.
	
	Args:
		to_email: Email address to send summary to (defaults to config file email)
	"""
	if to_email is None:
		try:
			config = load_config()
			to_email = config["email"]
		except (FileNotFoundError, ValueError) as e:
			return f"Error loading email configuration: {str(e)}"
	if not alert_history:
		return "No weather alert history to send."
	
	subject = "Weather Alert Summary"
	body = f"""Weather Alert History Summary:

{chr(10).join(alert_history)}

This summary was generated automatically by your weather MCP server.
"""
	
	return await send_email(to_email, subject, body)

if __name__ == "__main__": 
	
	mcp.run(transport='stdio')
