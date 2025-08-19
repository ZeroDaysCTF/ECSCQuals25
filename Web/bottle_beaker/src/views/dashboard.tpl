% rebase('layout.tpl', title='Dashboard')

<div class="card">
    <div class="header">
        <h2>Glass storage 🫙🍾🫙🍾🫙🍾</h2>
        <form method="post" action="/logout" class="logout-form">
            <input type="submit" value="Logout">
        </form>
    </div>
    <p class="emoji-message">🔨🫙🍾💥?</p>
</div>

<div class="card">
    <h3>Upload File</h3>
    <form action="/upload" method="post" enctype="multipart/form-data">
        <input type="file" name="upload" required>
        <input type="submit" value="Upload">
    </form>
</div>

<div class="card">
    <h3>Your Files</h3>
    <ul>
        % if files:
            % for f in files:
                <li><a href="/files/{{f}}">{{f}}</a></li>
            % end
        % else:
            <li>No files uploaded.</li>
        % end
    </ul>
</div>
