**# CSS INFORMATION**
Im trying to make a soft, pastel-colored interface with a baby blue navbar and baby pink buttons. Here's a breakdown of the styles:

**## Navbar:**
It uses a baby blue background (#89CFF0)
White text for links
Flex layout with 1rem gap between items
1rem padding all around

**## Flash Messages:**
Success messages in pastel green (#B5EAD7)
Danger/error messages in baby pink (#FFD1DC)
Rounded corners (4px radius)
1rem margin and padding

**## Buttons:**
Baby pink background (#FFD1DC)
No border
Rounded corners (4px radius)
Hover effect that reduces opacity
0.5rem vertical and 1rem horizontal padding

**## Tables:**
Full width with collapsed borders
Baby blue header (#89CFF0) with white text
Light gray bottom border for cells (#ddd)
0.5rem padding in cells
1rem margin above and below tables

**## General:**
Uses Arial as the primary font with sans-serif fallback
Dark gray text (#333)
No default margin or padding on the 

i hope to get a soft, friendly appearance that would work well for applications. im targeting younger guys as these days its all about aesthetic. something is telling me to try browns. i think browns look so pretty but i do not know shades of brown so we shall risk it with these. i hope my app looks interesting and aesthetic. i started here cos i think this is the easiest part. in my other trial i tried to start with backend and if im being honest, i dread reaching that part but i will figure it out i know. ;.((

# ***Monday 16 June***

## **TODAY I WORKED ON MY LOGIN PAGE**: 
 I intend to have a main html file where every other html file will connect. I started with the login and I will make the base last once ive defined everything else I could start with it  but I feel like I could miss something so we will make all other html templates first and finish with base so that we have a full list of templates and we just connect them at once (subject to schnage at any time)

### 1.```python (not everything here is python but readme files are difficult to edit, so...)
 {% extends "base.html" %}
```
This template will insert its content into base.html where {% block content %} is defined and will help avoid repeating header/footer/navigation code.

### 2. {% block content %}
The content inside this block will replace the corresponding {% block content %} in base.html.
it ends with {% endblock %}.

### 3.<div style="max-width: 500px; margin: 2rem auto; background: #B5EAD7; padding: 2rem;">
this line creates a styled container [what people will see] for the login form.

Styles applied:
max-width: 500px → will Limit the width to 500px.
margin: 2rem auto → will add the top/bottom margin and center horizontally.
background: #B5EAD7; → Light green background.
padding: 2rem → to add internal spacing.

### 4.<h2 style="color: #333;">Login</h2>
This will display a heading ("Login").

Styles applied:
color: #333 → Dark gray text.

### 5. <form method="POST">
this will define a form that submits data via HTTP POST
When submitted, the form will send username and password to the server.
I will include a route to it in the backend code to handle it. 

### 6. Username Input Field
html
<div style="margin-bottom: 1rem;">
    <label>Username:</label>
    <input type="text" name="username" required style="width: 100%; padding: 0.5rem;">
</div>
Structure:
A div container with margin-bottom for spacing.
A label ("Username:") describing the input.
An input field for the username.
Key attributes:
type="text" → Text input.
name="username" → Key used when submitting data to the server.
required → Forces user to fill this field.
style="width: 100%; padding: 0.5rem;" → Full-width input with padding.

### 7. Password Input Field
html
<div style="margin-bottom: 1rem;">
    <label>Password:</label>
    <input type="password" name="password" required style="width: 100%; padding: 0.5rem;">
</div>
Similar to username but:
type="password" → Masks input (shows dots instead of text).
name="password" → Key for the password in form submission.

### 8. Submit Button
html
<button type="submit" style="background: #89CFF0; color: white; border: none; padding: 0.5rem 1rem;">Login</button>
there will be a button to submit the form.
Key attributes:
type="submit" → will trigger form submission.
Styles applied:
background: #89CFF0 → Light blue background.
color: white → White text.
border: none → Removes default border.
padding: 0.5rem 1rem → Adds internal spacing.

### 9. {% endblock %}
this will close the {% block content %} section so that everything between {% block content %} and {% endblock %} is inserted into base.html.
