/* Secure SDLC Evidence Collector - main UI script
   - Reveal on scroll (IntersectionObserver)
   - Animated counters
   - 3D tilt on key cards
   - Animated meters
   - Motion toggle
   - Navigation state (active link per section)
*/
(function () {
  "use strict";

  const mediaRM = window.matchMedia("(prefers-reduced-motion: reduce)");
  const body = document.body;

  // --- MOTION TOGGLE ---------------------------------------------------------
  const motionBtn = document.querySelector("[data-toggle-motion]");
  function applyMotionState(on) {
    body.dataset.motion = on ? "on" : "off";
    if (motionBtn) {
      motionBtn.setAttribute("aria-pressed", on ? "true" : "false");
      motionBtn.querySelector(".btn__label").textContent = on ? "Motion" : "Motion off";
    }
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

  // --- REVEAL ON SCROLL ------------------------------------------------------
  const reveals = document.querySelectorAll("[data-reveal]");
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

  // --- COUNTERS --------------------------------------------------------------
  function easeOutCubic(t) { return 1 - Math.pow(1 - t, 3); }
  function animateCounter(el) {
    const target = parseFloat(el.getAttribute("data-counter"));
    const suffix = el.getAttribute("data-suffix") || "";
    if (isNaN(target)) return;
    const duration = 1400;
    const start = performance.now();
    const isInt = Number.isInteger(target);
    function tick(now) {
      const t = Math.min(1, (now - start) / duration);
      const v = target * easeOutCubic(t);
      el.textContent = (isInt ? Math.round(v) : v.toFixed(1)) + suffix;
      if (t < 1) requestAnimationFrame(tick);
      else el.textContent = (isInt ? target : target.toFixed(1)) + suffix;
    }
    requestAnimationFrame(tick);
  }
  const counters = document.querySelectorAll("[data-counter]");
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
    counters.forEach(animateCounter);
  }

  // --- METERS ----------------------------------------------------------------
  const meters = document.querySelectorAll("[data-meter]");
  function fillMeter(container) {
    const target = parseInt(container.getAttribute("data-meter"), 10);
    if (isNaN(target)) return;
    const bar = container.querySelector("[data-bar]");
    const label = container.querySelector(".meter__value");
    if (!bar) return;
    requestAnimationFrame(() => { bar.style.width = target + "%"; });
    if (label) {
      const start = performance.now();
      const dur = 1200;
      function tick(now) {
        const t = Math.min(1, (now - start) / dur);
        label.textContent = Math.round(target * easeOutCubic(t));
        if (t < 1) requestAnimationFrame(tick);
      }
      requestAnimationFrame(tick);
    }
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
    meters.forEach(fillMeter);
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
  const sections = Array.from(navLinks)
    .map((a) => document.querySelector(a.getAttribute("href")))
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
