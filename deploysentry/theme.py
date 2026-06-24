CYBERPUNK_CSS = """
Screen { background: #05070d; color: #d8fff8; }
Header { background: #07111f; color: #39fff3; text-style: bold; }
Footer { background: #07111f; color: #ff3df2; }

#top {
    height: 12;
    min-height: 12;
    border: heavy #39fff3;
    padding: 1;
    background: #090d18;
}

#title { color: #39fff3; text-style: bold; height: 1; }

#target-row {
    layout: horizontal;
    height: 3;
    min-height: 3;
}

#network-row {
    layout: horizontal;
    height: 3;
    min-height: 3;
    margin-top: 1;
}

#target-label,
#network-label {
    width: 9;
    height: 3;
    content-align: left middle;
    color: #d8fff8;
}

#shortcut-help {
    height: 3;
    content-align: left middle;
    color: #6f8799;
    padding-left: 1;
}

/* Textual's Input renders the typed value through component classes on many
   versions. Style the widget and internal components explicitly so the text is
   visible on the dark cyberpunk background. */
Input {
    height: 3;
    min-height: 3;
    max-height: 3;
    padding: 0 1;
    border: tall #39fff3;
    background: #03050a;
    color: #d8fff8;
}

#domain {
    width: 125;
}

Input:focus {
    border: heavy #55ff99;
    background: #07111f;
    color: #ffffff;
}
Input > .input--placeholder { color: #6f8799; }
Input:focus > .input--placeholder { color: #8fffee; }
Input > .input--cursor {
    color: #05070d;
    background: #39fff3;
    text-style: bold;
}
Input:focus > .input--cursor {
    color: #05070d;
    background: #55ff99;
    text-style: bold;
}
Input > .input--selection {
    color: #05070d;
    background: #ff3df2;
}
Input > .input--suggestion { color: #55ff99; }

Button {
    height: 3;
    min-height: 3;
    border: tall #ff3df2;
    background: #0d1020;
    color: #d8fff8;
}
Button:hover { background: #1a1430; }
#toggle-proxies { border: tall #ffd166; }
#toggle-tor { border: tall #39fff3; }
#toggle-pro { border: tall #55ff99; }

DataTable { border: heavy #39fff3; background: #050913; height: 1fr; width: 100%; }
#findings { border: heavy #ff3df2; }
#log { border: heavy #55ff99; height: 10; background: #03050a; }
#status { border: heavy #ffd166; height: 3; background: #090d18; }
#assets { width: 100%; height: 1fr; }
.panel-title { color: #ff3df2; text-style: bold; }
"""
