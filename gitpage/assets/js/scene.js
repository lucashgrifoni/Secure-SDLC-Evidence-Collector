/* Secure SDLC Evidence Collector - hero 3D scene
   Three.js UMD global: THREE
   Concept:
   - Central "Evidence Core" (wireframe icosahedron) represents the canonical bundle.
   - Orbital nodes represent evidence sources (SAST, SCA, SBOM, PR, Release...).
   - Particles with lines = lineage / data packets.
   - Camera parallax via mouse + smooth rotation.
   - Pauses when the tab is inactive.
   - Respects prefers-reduced-motion.
   - Fallback when WebGL is not available. */

(function () {
  "use strict";

  const canvas = document.getElementById("hero-canvas");
  if (!canvas) return;
  if (typeof THREE === "undefined") return;

  // Reduced motion
  const mediaRM = window.matchMedia("(prefers-reduced-motion: reduce)");
  const reducedMotion = () => mediaRM.matches || document.body.dataset.motion === "off";

  // WebGL support check
  function webglSupported() {
    try {
      const c = document.createElement("canvas");
      return !!(window.WebGLRenderingContext && (c.getContext("webgl") || c.getContext("experimental-webgl")));
    } catch (e) { return false; }
  }

  if (!webglSupported()) {
    canvas.style.display = "none";
    return;
  }

  const PALETTE = {
    bg:       0x0c124c,
    text:     0xd5d8dd,
    accent:   0x08b98b,
    accent2:  0x0fd6a0,
    muted:    0x7c8394,
    muted2:   0x5a6876
  };

  const container = canvas.parentElement;
  let w = container.clientWidth;
  let h = container.clientHeight;

  const renderer = new THREE.WebGLRenderer({
    canvas,
    antialias: true,
    alpha: true,
    powerPreference: "high-performance"
  });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  renderer.setSize(w, h, false);
  renderer.setClearColor(0x000000, 0);

  const scene = new THREE.Scene();
  scene.fog = new THREE.Fog(PALETTE.bg, 10, 30);

  const camera = new THREE.PerspectiveCamera(55, w / h, 0.1, 100);
  camera.position.set(0, 0, 8.2);

  // --- Lights ----------------------------------------------------------------
  scene.add(new THREE.AmbientLight(0x6a7a8a, 0.8));
  const dir = new THREE.DirectionalLight(PALETTE.accent, 1.2);
  dir.position.set(4, 6, 6);
  scene.add(dir);
  const dir2 = new THREE.DirectionalLight(0xd5d8dd, 0.35);
  dir2.position.set(-6, -3, 2);
  scene.add(dir2);

  // --- Root group that we tilt via mouse ------------------------------------
  const world = new THREE.Group();
  scene.add(world);

  // --- Evidence Core (central icosaedro) ------------------------------------
  const coreGroup = new THREE.Group();
  world.add(coreGroup);

  // Inner solid mesh (very subtle, gives volume)
  const coreInnerGeom = new THREE.IcosahedronGeometry(1.0, 1);
  const coreInnerMat  = new THREE.MeshStandardMaterial({
    color: 0x0a1555,
    metalness: 0.6,
    roughness: 0.35,
    emissive: 0x040a2a,
    flatShading: true,
    transparent: true,
    opacity: 0.85
  });
  const coreInner = new THREE.Mesh(coreInnerGeom, coreInnerMat);
  coreGroup.add(coreInner);

  // Outer wireframe
  const coreOuterGeom = new THREE.IcosahedronGeometry(1.25, 1);
  const coreEdges = new THREE.LineSegments(
    new THREE.EdgesGeometry(coreOuterGeom),
    new THREE.LineBasicMaterial({ color: PALETTE.accent, transparent: true, opacity: 0.85 })
  );
  coreGroup.add(coreEdges);

  // Outermost halo wireframe
  const coreHaloGeom = new THREE.IcosahedronGeometry(1.6, 0);
  const coreHalo = new THREE.LineSegments(
    new THREE.EdgesGeometry(coreHaloGeom),
    new THREE.LineBasicMaterial({ color: PALETTE.text, transparent: true, opacity: 0.15 })
  );
  coreGroup.add(coreHalo);

  // Small pulse sphere at center
  const pulseGeom = new THREE.SphereGeometry(0.16, 24, 24);
  const pulseMat = new THREE.MeshBasicMaterial({ color: PALETTE.accent2 });
  const pulse = new THREE.Mesh(pulseGeom, pulseMat);
  coreGroup.add(pulse);

  // --- Orbital rings (3 of them at different tilts) -------------------------
  const ringsGroup = new THREE.Group();
  world.add(ringsGroup);

  function makeRing(radius, tilt, color, opacity) {
    const curve = new THREE.EllipseCurve(0, 0, radius, radius, 0, Math.PI * 2, false, 0);
    const pts = curve.getPoints(128);
    const geom = new THREE.BufferGeometry().setFromPoints(pts.map(p => new THREE.Vector3(p.x, 0, p.y)));
    const mat = new THREE.LineBasicMaterial({ color, transparent: true, opacity });
    const line = new THREE.Line(geom, mat);
    line.rotation.x = tilt.x;
    line.rotation.z = tilt.z;
    return line;
  }

  const ring1 = makeRing(2.3, { x: Math.PI / 2.6, z: 0.2 }, PALETTE.muted, 0.25);
  const ring2 = makeRing(3.1, { x: Math.PI / 3.3, z: -0.35 }, PALETTE.muted, 0.18);
  const ring3 = makeRing(4.0, { x: Math.PI / 2.2, z: 0.55 }, PALETTE.accent, 0.18);
  ringsGroup.add(ring1, ring2, ring3);

  // --- Orbiting evidence nodes ---------------------------------------------
  const nodes = [];
  const nodeDefs = [
    { ring: 0, radius: 2.3, speed: 0.42, phase: 0.0,              color: PALETTE.accent,  size: 0.10 },
    { ring: 0, radius: 2.3, speed: 0.42, phase: Math.PI * 0.66,   color: PALETTE.text,    size: 0.07 },
    { ring: 0, radius: 2.3, speed: 0.42, phase: Math.PI * 1.33,   color: PALETTE.accent,  size: 0.08 },
    { ring: 1, radius: 3.1, speed: -0.28, phase: 0.3,             color: PALETTE.muted,   size: 0.06 },
    { ring: 1, radius: 3.1, speed: -0.28, phase: Math.PI * 0.6,   color: PALETTE.accent,  size: 0.09 },
    { ring: 1, radius: 3.1, speed: -0.28, phase: Math.PI,         color: PALETTE.text,    size: 0.07 },
    { ring: 1, radius: 3.1, speed: -0.28, phase: Math.PI * 1.5,   color: PALETTE.accent,  size: 0.08 },
    { ring: 2, radius: 4.0, speed: 0.18,  phase: 0.0,             color: PALETTE.accent2, size: 0.11 },
    { ring: 2, radius: 4.0, speed: 0.18,  phase: Math.PI * 0.5,   color: PALETTE.text,    size: 0.08 },
    { ring: 2, radius: 4.0, speed: 0.18,  phase: Math.PI,         color: PALETTE.accent,  size: 0.10 },
    { ring: 2, radius: 4.0, speed: 0.18,  phase: Math.PI * 1.5,   color: PALETTE.muted,   size: 0.07 }
  ];
  const ringTilts = [
    { x: Math.PI / 2.6, z: 0.2 },
    { x: Math.PI / 3.3, z: -0.35 },
    { x: Math.PI / 2.2, z: 0.55 }
  ];
  const ringMatrix = ringTilts.map(t => {
    const m = new THREE.Matrix4();
    m.makeRotationFromEuler(new THREE.Euler(t.x, 0, t.z, "XYZ"));
    return m;
  });

  const nodeGeom = new THREE.SphereGeometry(1, 14, 14);
  nodeDefs.forEach((d) => {
    const mat = new THREE.MeshBasicMaterial({ color: d.color, transparent: true, opacity: 0.95 });
    const mesh = new THREE.Mesh(nodeGeom, mat);
    mesh.scale.setScalar(d.size);
    const glowMat = new THREE.SpriteMaterial({
      color: d.color,
      transparent: true,
      opacity: 0.45,
      blending: THREE.AdditiveBlending,
      depthWrite: false
    });
    const glow = new THREE.Sprite(glowMat);
    glow.scale.setScalar(d.size * 5.5);
    mesh.add(glow);
    world.add(mesh);
    nodes.push({ mesh, def: d });
  });

  // --- Particle field with connecting lines ---------------------------------
  const PARTICLE_COUNT = 240;
  const particleGeom = new THREE.BufferGeometry();
  const positions = new Float32Array(PARTICLE_COUNT * 3);
  const velocities = new Float32Array(PARTICLE_COUNT * 3);
  for (let i = 0; i < PARTICLE_COUNT; i++) {
    const r = 4 + Math.random() * 5;
    const theta = Math.random() * Math.PI * 2;
    const phi = Math.acos(2 * Math.random() - 1);
    positions[i * 3 + 0] = r * Math.sin(phi) * Math.cos(theta);
    positions[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta) * 0.6;
    positions[i * 3 + 2] = r * Math.cos(phi);
    velocities[i * 3 + 0] = (Math.random() - 0.5) * 0.003;
    velocities[i * 3 + 1] = (Math.random() - 0.5) * 0.003;
    velocities[i * 3 + 2] = (Math.random() - 0.5) * 0.003;
  }
  particleGeom.setAttribute("position", new THREE.BufferAttribute(positions, 3));

  // Tiny dot sprite for particles
  function makeDotTexture() {
    const size = 64;
    const c = document.createElement("canvas");
    c.width = c.height = size;
    const ctx = c.getContext("2d");
    const g = ctx.createRadialGradient(size / 2, size / 2, 0, size / 2, size / 2, size / 2);
    g.addColorStop(0,   "rgba(213,216,221,1)");
    g.addColorStop(0.4, "rgba(213,216,221,.5)");
    g.addColorStop(1,   "rgba(213,216,221,0)");
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, size, size);
    const t = new THREE.CanvasTexture(c);
    t.needsUpdate = true;
    return t;
  }

  const particleMat = new THREE.PointsMaterial({
    size: 0.09,
    map: makeDotTexture(),
    transparent: true,
    opacity: 0.75,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
    color: PALETTE.text
  });
  const points = new THREE.Points(particleGeom, particleMat);
  world.add(points);

  // Connecting lines (dynamic) - only between nearby particles
  const MAX_LINE_SEGMENTS = 160;
  const lineGeom = new THREE.BufferGeometry();
  const linePositions = new Float32Array(MAX_LINE_SEGMENTS * 2 * 3);
  const lineColors    = new Float32Array(MAX_LINE_SEGMENTS * 2 * 3);
  lineGeom.setAttribute("position", new THREE.BufferAttribute(linePositions, 3));
  lineGeom.setAttribute("color",    new THREE.BufferAttribute(lineColors, 3));
  lineGeom.setDrawRange(0, 0);
  const lineMat = new THREE.LineBasicMaterial({
    vertexColors: true,
    transparent: true,
    opacity: 0.55,
    blending: THREE.AdditiveBlending,
    depthWrite: false
  });
  const lines = new THREE.LineSegments(lineGeom, lineMat);
  world.add(lines);

  // --- Lineage streams: packets flowing core<->nodes -------------------------
  const STREAM_COUNT = 14;
  const streamGeom = new THREE.BufferGeometry();
  const streamPos = new Float32Array(STREAM_COUNT * 3);
  streamGeom.setAttribute("position", new THREE.BufferAttribute(streamPos, 3));
  const streamMat = new THREE.PointsMaterial({
    size: 0.18,
    map: makeDotTexture(),
    color: PALETTE.accent,
    transparent: true,
    opacity: 0.95,
    blending: THREE.AdditiveBlending,
    depthWrite: false
  });
  const streams = new THREE.Points(streamGeom, streamMat);
  world.add(streams);
  const streamState = [];
  for (let i = 0; i < STREAM_COUNT; i++) {
    streamState.push({
      t: Math.random(),
      speed: 0.35 + Math.random() * 0.4,
      nodeIdx: Math.floor(Math.random() * nodes.length),
      dir: Math.random() > 0.5 ? 1 : -1
    });
  }

  // --- Mouse parallax --------------------------------------------------------
  const mouse = { x: 0, y: 0, tx: 0, ty: 0 };
  function onPointerMove(e) {
    if (reducedMotion()) return;
    const rect = canvas.getBoundingClientRect();
    const px = (e.touches ? e.touches[0].clientX : e.clientX) - rect.left;
    const py = (e.touches ? e.touches[0].clientY : e.clientY) - rect.top;
    mouse.tx = (px / rect.width)  * 2 - 1;
    mouse.ty = (py / rect.height) * 2 - 1;
  }
  window.addEventListener("pointermove", onPointerMove, { passive: true });
  window.addEventListener("touchmove",  onPointerMove, { passive: true });

  // --- Resize ---------------------------------------------------------------
  function resize() {
    w = container.clientWidth;
    h = container.clientHeight;
    if (w === 0 || h === 0) return;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  }
  window.addEventListener("resize", resize);

  // --- Tab visibility --------------------------------------------------------
  let running = true;
  document.addEventListener("visibilitychange", () => {
    running = !document.hidden;
    if (running) lastTime = performance.now();
  });

  // --- Node position helper -------------------------------------------------
  const tmpVec = new THREE.Vector3();
  function nodePosition(def, time, out) {
    const angle = def.phase + time * def.speed;
    const x = Math.cos(angle) * def.radius;
    const z = Math.sin(angle) * def.radius;
    out.set(x, 0, z).applyMatrix4(ringMatrix[def.ring]);
    return out;
  }

  // --- Animation loop -------------------------------------------------------
  const clock = new THREE.Clock();
  let lastTime = performance.now();

  function animate() {
    if (!running) { requestAnimationFrame(animate); return; }

    const dt = clock.getDelta();
    const elapsed = clock.getElapsedTime();
    const rm = reducedMotion();
    const speedScale = rm ? 0.15 : 1.0;

    // Mouse easing
    mouse.x += (mouse.tx - mouse.x) * 0.05;
    mouse.y += (mouse.ty - mouse.y) * 0.05;
    world.rotation.y = mouse.x * 0.35;
    world.rotation.x = -mouse.y * 0.25;

    // Core rotation + pulse
    coreGroup.rotation.y += dt * 0.12 * speedScale;
    coreGroup.rotation.x += dt * 0.05 * speedScale;
    coreHalo.rotation.y -= dt * 0.08 * speedScale;
    const pulseScale = 1 + Math.sin(elapsed * 2.5) * 0.35;
    pulse.scale.setScalar(pulseScale);
    pulse.material.opacity = 0.7 + Math.sin(elapsed * 2.5) * 0.25;

    // Orbital rings slow rotation
    ringsGroup.rotation.y += dt * 0.04 * speedScale;

    // Nodes orbiting
    nodes.forEach((n) => {
      nodePosition(n.def, elapsed * speedScale, tmpVec);
      n.mesh.position.copy(tmpVec);
    });

    // Particles drift
    if (!rm) {
      const arr = particleGeom.attributes.position.array;
      for (let i = 0; i < PARTICLE_COUNT; i++) {
        arr[i * 3 + 0] += velocities[i * 3 + 0];
        arr[i * 3 + 1] += velocities[i * 3 + 1];
        arr[i * 3 + 2] += velocities[i * 3 + 2];
        // Bounce softly in a bounding sphere
        const x = arr[i*3], y = arr[i*3+1], z = arr[i*3+2];
        const d = Math.sqrt(x*x + y*y + z*z);
        if (d > 9.5) {
          velocities[i * 3 + 0] *= -1;
          velocities[i * 3 + 1] *= -1;
          velocities[i * 3 + 2] *= -1;
        }
      }
      particleGeom.attributes.position.needsUpdate = true;
    }

    // Build connecting lines between close particles (subset per frame for perf)
    const posArr = particleGeom.attributes.position.array;
    let seg = 0;
    const threshold = 1.2;
    const threshold2 = threshold * threshold;
    const step = Math.max(1, Math.floor(PARTICLE_COUNT / 120));
    for (let i = 0; i < PARTICLE_COUNT && seg < MAX_LINE_SEGMENTS; i += step) {
      const ax = posArr[i*3], ay = posArr[i*3+1], az = posArr[i*3+2];
      for (let j = i + step; j < PARTICLE_COUNT && seg < MAX_LINE_SEGMENTS; j += step) {
        const bx = posArr[j*3], by = posArr[j*3+1], bz = posArr[j*3+2];
        const dx = ax - bx, dy = ay - by, dz = az - bz;
        const d2 = dx*dx + dy*dy + dz*dz;
        if (d2 < threshold2) {
          const alpha = 1.0 - d2 / threshold2;
          linePositions[seg*6 + 0] = ax; linePositions[seg*6 + 1] = ay; linePositions[seg*6 + 2] = az;
          linePositions[seg*6 + 3] = bx; linePositions[seg*6 + 4] = by; linePositions[seg*6 + 5] = bz;
          // accent tint weighted by alpha
          const r = 0.03 + alpha * 0.03;
          const g = 0.72 + alpha * 0.2;
          const b = 0.54 + alpha * 0.15;
          lineColors[seg*6 + 0] = r; lineColors[seg*6 + 1] = g; lineColors[seg*6 + 2] = b;
          lineColors[seg*6 + 3] = r; lineColors[seg*6 + 4] = g; lineColors[seg*6 + 5] = b;
          seg++;
        }
      }
    }
    lineGeom.setDrawRange(0, seg * 2);
    lineGeom.attributes.position.needsUpdate = true;
    lineGeom.attributes.color.needsUpdate = true;

    // Stream packets core <-> nodes
    for (let i = 0; i < STREAM_COUNT; i++) {
      const s = streamState[i];
      s.t += dt * s.speed * speedScale;
      if (s.t > 1) {
        s.t = 0;
        s.nodeIdx = Math.floor(Math.random() * nodes.length);
        s.dir = Math.random() > 0.5 ? 1 : -1;
      }
      const node = nodes[s.nodeIdx];
      nodePosition(node.def, elapsed * speedScale, tmpVec);
      const k = s.dir === 1 ? s.t : 1 - s.t;
      streamPos[i * 3 + 0] = tmpVec.x * k;
      streamPos[i * 3 + 1] = tmpVec.y * k + Math.sin(s.t * Math.PI) * 0.12;
      streamPos[i * 3 + 2] = tmpVec.z * k;
    }
    streamGeom.attributes.position.needsUpdate = true;

    renderer.render(scene, camera);
    requestAnimationFrame(animate);
  }

  // Kick off
  resize();
  animate();

  // Expose a tiny API
  window.__hero3D = {
    setMotion(on) {
      if (on) {
        canvas.style.opacity = "";
      } else {
        canvas.style.opacity = "0.6";
      }
    }
  };
})();
