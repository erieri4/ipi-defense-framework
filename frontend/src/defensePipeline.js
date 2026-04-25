const API_BASE_URL = "http://127.0.0.1:8000";

export async function evaluatePrompt(prompt) {
  const response = await fetch(`${API_BASE_URL}/validate`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ prompt }),
  });

  if (!response.ok) {
    throw new Error(`Validation request failed with status ${response.status}.`);
  }

  return response.json();
}
