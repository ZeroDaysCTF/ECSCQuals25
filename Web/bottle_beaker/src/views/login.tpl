% rebase('layout.tpl', title='Login')

<h2>Login</h2>
<form method="post" action="/login">
    <input type="text" name="username" placeholder="Username" required>
    <input type="password" name="password" placeholder="Password" required>
    <input type="submit" value="Login">
</form>

<h2>Register</h2>
<form method="post" action="/register">
    <input type="text" name="username" placeholder="New Username" required>
    <input type="password" name="password" placeholder="New Password" required>
    <input type="submit" value="Register">
</form>
