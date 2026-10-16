/* Secure SDLC Evidence Collector - main UI script
   - Reveal on scroll (IntersectionObserver)
   - Animated counters
   - 3D tilt on key cards
   - Animated meters
   - Motion toggle
   - Navigation state (active link per section) and the small-screen menu

   The HTML ships every final value and every section visible. Content is
   hidden for a reveal, or reset to zero for a count-up, only when this script
   runs with motion on, so the page reads the same without JavaScript, in
   print, and with reduced motion.
*/
(function () {
  "use strict";

  const mediaRM = window.matchMedia("(prefers-reduced-motion: reduce)");
  const body = document.body;
  const reveals = document.querySelectorAll("[data-reveal]");
  const counters = document.querySelectorAll("[data-counter]");
  const meters = document.querySelectorAll("[data-meter]");
  const motionOn = () => body.dataset.motion !== "off";

  // --- COUNTERS AND METERS ---------------------------------------------------
  function easeOutCubic(t) { return 1 - Math.pow(1 - t, 3); }

  function counterText(el, value) {
    const target = parseFloat(el.getAttribute("data-counter"));
    const suffix = el.getAttribute("data-suffix") || "";
    return (Number.isInteger(target) ? Math.round(value) : value.toFixed(1)) + suffix;
  }
  function finishCounter(el) {
    const target = parseFloat(el.getAttribute("data-counter"));
    if (isNaN(target)) return;
    el.dataset.state = "done";
    el.textContent = counterText(el, target);
  }
  function animateCounter(el) {
    const target = parseFloat(el.getAttribute("data-counter"));
    if (isNaN(target) || el.dataset.state === "done") return;
    if (!motionOn()) { finishCounter(el); return; }
    const duration = 1400;
    const start = performance.now();
    function tick(now) {
      if (el.dataset.state === "done") return;
      const t = Math.min(1, (now - start) / duration);
      el.textContent = counterText(el, target * easeOutCubic(t));
      if (t < 1) requestAnimationFrame(tick);
      else finishCounter(el);
    }
    requestAnimationFrame(tick);
  }

  function finishMeter(container) {
    const target = parseInt(container.getAttribute("data-meter"), 10);
    if (isNaN(target)) return;
    container.dataset.state = "done";
    container.classList.add("is-filled");
    const label = container.querySelector(".meter__value");
    if (label) label.textContent = String(target);
  }
  function fillMeter(container) {
    const target = parseInt(container.getAttribute("data-meter"), 10);
    if (isNaN(target) || container.dataset.state === "done") return;
    if (!motionOn()) { finishMeter(container); return; }
    // The bar width comes from the --w custom property in the HTML; adding
    // is-filled lifts the zero width that motion mode applies in CSS.
    container.classList.add("is-filled");
    const label = container.querySelector(".meter__value");
    if (!label) { finishMeter(container); return; }
    const start = performance.now();
    const dur = 1200;
    function tick(now) {
      if (container.dataset.state === "done") return;
      const t = Math.min(1, (now - start) / dur);
      label.textContent = String(Math.round(target * easeOutCubic(t)));
      if (t < 1) requestAnimationFrame(tick);
      else finishMeter(container);
    }
    requestAnimationFrame(tick);
  }

  function finishCountersAndMeters() {
    counters.forEach(finishCounter);
    meters.forEach(finishMeter);
  }

  // --- MOTION TOGGLE ---------------------------------------------------------
  // The visible label stays "Motion"; aria-pressed alone carries the state, so a
  // screen reader never hears "Motion off, not pressed".
  const motionBtn = document.querySelector("[data-toggle-motion]");
  function applyMotionState(on) {
    body.dataset.motion = on ? "on" : "off";
    if (motionBtn) motionBtn.setAttribute("aria-pressed", on ? "true" : "false");
    if (!on) finishCountersAndMeters();
    if (window.__hero3D) window.__hero3D.setMotion(on);
  }
  // Default: on, unless system asks for reduced motion
  applyMotionState(!mediaRM.matches);
  if (motionBtn) {
    motionBtn.addEventListener("click", () => {
      const next = body.dataset.motion !== "on";
      applyMotionState(next);
    });
  }

  // With motion on, numbers count up from zero when they scroll into view.
  if (motionOn()) {
    counters.forEach((el) => {
      if (!isNaN(parseFloat(el.getAttribute("data-counter")))) el.textContent = counterText(el, 0);
    });
    meters.forEach((m) => {
      const label = m.querySelector(".meter__value");
      if (label) label.textContent = "0";
    });
  }

  // --- REVEAL ON SCROLL ------------------------------------------------------
  if ("IntersectionObserver" in window && reveals.length) {
    const io = new IntersectionObserver((entries) => {
      entries.forEach((en) => {
        if (en.isIntersecting) {
          const el = en.target;
          const delay = parseInt(el.getAttribute("data-reveal-delay") || "0", 10);
          setTimeout(() => el.classList.add("is-in"), delay);
          io.unobserve(el);
        }
      });
    }, { threshold: 0.14, rootMargin: "0px 0px -40px 0px" });
    reveals.forEach((el) => io.observe(el));
  } else {
    reveals.forEach((el) => el.classList.add("is-in"));
  }

  if ("IntersectionObserver" in window && counters.length) {
    const co = new IntersectionObserver((entries) => {
      entries.forEach((en) => {
        if (en.isIntersecting) {
          animateCounter(en.target);
          co.unobserve(en.target);
        }
      });
    }, { threshold: 0.4 });
    counters.forEach((el) => co.observe(el));
  } else {
    counters.forEach(finishCounter);
  }

  if ("IntersectionObserver" in window && meters.length) {
    const mo = new IntersectionObserver((entries) => {
      entries.forEach((en) => {
        if (en.isIntersecting) {
          fillMeter(en.target);
          mo.unobserve(en.target);
        }
      });
    }, { threshold: 0.4 });
    meters.forEach((m) => mo.observe(m));
  } else {
    meters.forEach(finishMeter);
  }

  // Printing before scrolling must not leave blank sections or zeroed numbers.
  window.addEventListener("beforeprint", () => {
    reveals.forEach((el) => el.classList.add("is-in"));
    finishCountersAndMeters();
  });

  // --- SMALL-SCREEN MENU -----------------------------------------------------
  // A native <details> works without JavaScript; this only closes it after a
  // link is chosen or Escape is pressed.
  const menu = document.querySelector(".nav__menu");
  if (menu) {
    menu.addEventListener("click", (e) => {
      if (e.target.closest("a")) menu.open = false;
    });
    menu.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && menu.open) {
        menu.open = false;
        menu.querySelector("summary").focus();
      }
    });
  }

  // --- TILT 3D ---------------------------------------------------------------
  const tilts = document.querySelectorAll(".tilt");
  tilts.forEach((el) => {
    let raf = 0;
    function onMove(e) {
      if (body.dataset.motion === "off") return;
      const rect = el.getBoundingClientRect();
      const x = (e.clientX - rect.left) / rect.width - 0.5;
      const y = (e.clientY - rect.top)  / rect.height - 0.5;
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => {
        el.style.transform = `perspective(800px) rotateY(${x * 6}deg) rotateX(${-y * 6}deg) translateZ(0)`;
      });
    }
    function reset() {
      cancelAnimationFrame(raf);
      el.style.transform = "";
    }
    el.addEventListener("pointermove", onMove);
    el.addEventListener("pointerleave", reset);
  });

  // --- ACTIVE NAV LINK -------------------------------------------------------
  const navLinks = document.querySelectorAll(".nav__links a");
  // Only in-page anchors map to sections; "docs/" is not a selector.
  const sections = Array.from(navLinks)
    .map((a) => a.getAttribute("href"))
    .filter((href) => href.startsWith("#"))
    .map((href) => document.querySelector(href))
    .filter(Boolean);

  if ("IntersectionObserver" in window && sections.length) {
    const sio = new IntersectionObserver((entries) => {
      entries.forEach((en) => {
        if (en.isIntersecting) {
          navLinks.forEach((a) => a.removeAttribute("aria-current"));
          const active = document.querySelector(`.nav__links a[href="#${en.target.id}"]`);
          if (active) active.setAttribute("aria-current", "true");
        }
      });
    }, { rootMargin: "-45% 0px -45% 0px", threshold: 0 });
    sections.forEach((s) => sio.observe(s));
  }

  // Smooth anchor scroll (already native via CSS) + focus management
  document.querySelectorAll('a[href^="#"]').forEach((a) => {
    a.addEventListener("click", (e) => {
      const id = a.getAttribute("href").slice(1);
      if (!id) return;
      const target = document.getElementById(id);
      if (target) {
        setTimeout(() => target.setAttribute("tabindex", "-1"), 0);
      }
    });
  });
})();
