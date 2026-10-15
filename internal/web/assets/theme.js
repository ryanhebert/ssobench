// Applies the saved theme before the page draws, so there is no flash of
// the wrong one. Loaded without defer, ahead of the stylesheet.
try {
  var t = localStorage.getItem("ssobench.theme");
  if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
} catch (e) {}
