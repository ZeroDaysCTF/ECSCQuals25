<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{title or "App"}}</title>
    <style>
        :root {
            --bg: #f8f9fa;
            --card-bg: #ffffff;
            --border: #dee2e6;
            --text: #212529;
            --accent: #0d6efd;
            --accent-hover: #0b5ed7;
            --muted: #6c757d;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
            margin: 2em auto;
            max-width: 720px;
            background-color: var(--bg);
            padding: 2em;
            color: var(--text);
        }

        h1, h2, h3 {
            margin-bottom: 0.5em;
        }

        .card {
            background-color: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5em;
            margin-top: 1.5em;
            box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
        }

        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .logout-form {
            margin: 0;
        }

        .logout-form input[type="submit"] {
            background-color: var(--accent);
            border: none;
            color: white;
            padding: 0.4em 1em;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.9em;
        }

        .logout-form input[type="submit"]:hover {
            background-color: var(--accent-hover);
        }

        .emoji-message {
            margin-top: 0.5em;
            font-size: 1.2em;
            color: var(--muted);
        }

        form input[type="file"],
        form input[type="text"],
        form input[type="password"] {
            width: 100%;
            padding: 0.5em;
            margin: 0.5em 0 1em 0;
            border: 1px solid var(--border);
            border-radius: 4px;
            background: white;
        }

        form input[type="submit"] {
            background-color: var(--accent);
            color: white;
            border: none;
            padding: 0.5em 1.2em;
            border-radius: 4px;
            cursor: pointer;
        }

        form input[type="submit"]:hover {
            background-color: var(--accent-hover);
        }

        ul {
            padding-left: 1.2em;
            margin-top: 1em;
        }

        li {
            margin-bottom: 0.5em;
        }

        a {
            color: var(--accent);
            text-decoration: none;
        }

        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div>
        {{!base}}
    </div>
</body>
</html>
