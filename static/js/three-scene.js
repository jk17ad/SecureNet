/**
 * SecureNet — Advanced 3D Interface Engine
 * Powered by Three.js r128
 * Renders: Animated neural-network background, 3D threat globe, 3D network topology
 */

(function () {
    'use strict';

    /* =========================================================
     * 0. SHARED UTILITIES
     * ========================================================= */
    const rand = (min, max) => Math.random() * (max - min) + min;
    const isDark = () => document.documentElement.getAttribute('data-theme') !== 'light';

    /* Colour palettes */
    const DARK_COLORS = {
        node:        0x06b6d4,
        nodeSafe:    0x10b981,
        nodeDanger:  0xef4444,
        edge:        0x3b82f6,
        globe:       0x1e3a5f,
        globeGrid:   0x06b6d4,
        particle:    0x8b5cf6,
        bg:          0x000000,
    };
    const LIGHT_COLORS = {
        node:        0x0891b2,
        nodeSafe:    0x059669,
        nodeDanger:  0xdc2626,
        edge:        0x2563eb,
        globe:       0x93c5fd,
        globeGrid:   0x0891b2,
        particle:    0x7c3aed,
        bg:          0xffffff,
    };
    const C = () => isDark() ? DARK_COLORS : LIGHT_COLORS;

    /* =========================================================
     * 1. BACKGROUND SCENE — animated neural network particles
     * ========================================================= */
    function initBackground() {
        const canvas = document.getElementById('three-bg');
        if (!canvas) return;

        const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: false });
        renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.5));
        renderer.setSize(window.innerWidth, window.innerHeight);

        const scene = new THREE.Scene();
        const camera = new THREE.PerspectiveCamera(70, window.innerWidth / window.innerHeight, 0.1, 1000);
        camera.position.z = 60;

        /* --- Particles (constellation dots) --- */
        const PARTICLE_COUNT = 180;
        const positions = new Float32Array(PARTICLE_COUNT * 3);
        const particleColors = new Float32Array(PARTICLE_COUNT * 3);

        const colA = new THREE.Color(0x06b6d4);
        const colB = new THREE.Color(0x8b5cf6);
        const colC = new THREE.Color(0x3b82f6);
        const palette = [colA, colB, colC];

        for (let i = 0; i < PARTICLE_COUNT; i++) {
            positions[i * 3]     = rand(-90, 90);
            positions[i * 3 + 1] = rand(-55, 55);
            positions[i * 3 + 2] = rand(-40, 10);
            const col = palette[Math.floor(Math.random() * palette.length)];
            particleColors[i * 3]     = col.r;
            particleColors[i * 3 + 1] = col.g;
            particleColors[i * 3 + 2] = col.b;
        }

        const particleGeo = new THREE.BufferGeometry();
        particleGeo.setAttribute('position', new THREE.BufferAttribute(positions, 3));
        particleGeo.setAttribute('color', new THREE.BufferAttribute(particleColors, 3));

        const particleMat = new THREE.PointsMaterial({
            size: 0.55,
            vertexColors: true,
            transparent: true,
            opacity: isDark() ? 0.75 : 0.45,
            depthWrite: false,
        });

        const particles = new THREE.Points(particleGeo, particleMat);
        scene.add(particles);

        /* --- Connection lines between nearby particles --- */
        const lineMat = new THREE.LineBasicMaterial({
            color: 0x06b6d4,
            transparent: true,
            opacity: 0.09,
        });

        const THRESH = 28;
        const lineGroup = new THREE.Group();
        scene.add(lineGroup);

        function rebuildLines() {
            while (lineGroup.children.length) lineGroup.remove(lineGroup.children[0]);
            const pos = particleGeo.attributes.position.array;
            for (let i = 0; i < PARTICLE_COUNT; i++) {
                for (let j = i + 1; j < PARTICLE_COUNT; j++) {
                    const dx = pos[i * 3]     - pos[j * 3];
                    const dy = pos[i * 3 + 1] - pos[j * 3 + 1];
                    const dz = pos[i * 3 + 2] - pos[j * 3 + 2];
                    const dist = Math.sqrt(dx * dx + dy * dy + dz * dz);
                    if (dist < THRESH) {
                        const geo = new THREE.BufferGeometry().setFromPoints([
                            new THREE.Vector3(pos[i*3], pos[i*3+1], pos[i*3+2]),
                            new THREE.Vector3(pos[j*3], pos[j*3+1], pos[j*3+2]),
                        ]);
                        lineGroup.add(new THREE.Line(geo, lineMat));
                    }
                }
            }
        }
        rebuildLines();

        /* Mouse parallax */
        let mouseX = 0, mouseY = 0;
        document.addEventListener('mousemove', (e) => {
            mouseX = (e.clientX / window.innerWidth  - 0.5) * 2;
            mouseY = (e.clientY / window.innerHeight - 0.5) * 2;
        });

        let t = 0;
        function animate() {
            requestAnimationFrame(animate);
            t += 0.003;

            particles.rotation.y = t * 0.04 + mouseX * 0.04;
            particles.rotation.x = mouseY * 0.03;
            lineGroup.rotation.y = particles.rotation.y;
            lineGroup.rotation.x = particles.rotation.x;

            /* Gentle breathing opacity */
            particleMat.opacity = (isDark() ? 0.65 : 0.35) + Math.sin(t) * 0.08;

            renderer.render(scene, camera);
        }
        animate();

        window.addEventListener('resize', () => {
            camera.aspect = window.innerWidth / window.innerHeight;
            camera.updateProjectionMatrix();
            renderer.setSize(window.innerWidth, window.innerHeight);
        });

        /* Listen for theme toggle */
        document.addEventListener('themeChanged', () => {
            lineMat.color.set(isDark() ? 0x06b6d4 : 0x0891b2);
        });
    }

    /* =========================================================
     * 2. THREAT GLOBE — rotating Earth with threat markers
     * ========================================================= */
    function initThreatGlobe() {
        const canvas = document.getElementById('threat-globe-canvas');
        if (!canvas) return;

        const W = canvas.parentElement.clientWidth  || 420;
        const H = canvas.parentElement.clientHeight || 420;

        const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
        renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
        renderer.setSize(W, H);

        const scene = new THREE.Scene();
        const camera = new THREE.PerspectiveCamera(45, W / H, 0.1, 500);
        camera.position.z = 3.8;

        /* Ambient + directional light */
        scene.add(new THREE.AmbientLight(0x1a2a4a, 2.5));
        const dirLight = new THREE.DirectionalLight(0x06b6d4, 1.8);
        dirLight.position.set(5, 3, 5);
        scene.add(dirLight);
        const dirLight2 = new THREE.DirectionalLight(0x8b5cf6, 0.8);
        dirLight2.position.set(-5, -3, -5);
        scene.add(dirLight2);

        /* Globe sphere */
        const globeGeo = new THREE.SphereGeometry(1, 48, 48);
        const globeMat = new THREE.MeshPhongMaterial({
            color:     0x0a1628,
            emissive:  0x061020,
            specular:  0x06b6d4,
            shininess: 40,
            transparent: true,
            opacity: 0.92,
        });
        const globe = new THREE.Mesh(globeGeo, globeMat);
        scene.add(globe);

        /* Latitude / longitude grid lines */
        const gridGroup = new THREE.Group();
        const gridMat = new THREE.LineBasicMaterial({ color: 0x06b6d4, transparent: true, opacity: 0.2 });

        /* Latitude rings */
        for (let lat = -75; lat <= 75; lat += 15) {
            const r = Math.cos(lat * Math.PI / 180);
            const y = Math.sin(lat * Math.PI / 180);
            const pts = [];
            for (let i = 0; i <= 64; i++) {
                const a = (i / 64) * Math.PI * 2;
                pts.push(new THREE.Vector3(r * Math.cos(a), y, r * Math.sin(a)));
            }
            gridGroup.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts), gridMat));
        }

        /* Longitude meridians */
        for (let lon = 0; lon < 360; lon += 20) {
            const pts = [];
            for (let i = 0; i <= 64; i++) {
                const lat2 = (i / 64) * Math.PI * 2 - Math.PI / 2;
                const a2   = lon * Math.PI / 180;
                pts.push(new THREE.Vector3(
                    Math.cos(lat2) * Math.cos(a2),
                    Math.sin(lat2),
                    Math.cos(lat2) * Math.sin(a2)
                ));
            }
            gridGroup.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts), gridMat));
        }
        scene.add(gridGroup);

        /* Atmosphere glow (additive halo) */
        const atmosGeo = new THREE.SphereGeometry(1.08, 32, 32);
        const atmosMat = new THREE.MeshBasicMaterial({
            color:       0x06b6d4,
            transparent: true,
            opacity:     0.04,
            side:        THREE.BackSide,
        });
        scene.add(new THREE.Mesh(atmosGeo, atmosMat));

        /* Outer ring */
        const ringGeo = new THREE.TorusGeometry(1.22, 0.005, 8, 120);
        const ringMat = new THREE.MeshBasicMaterial({ color: 0x06b6d4, transparent: true, opacity: 0.3 });
        const ring = new THREE.Mesh(ringGeo, ringMat);
        ring.rotation.x = Math.PI / 2.3;
        scene.add(ring);

        /* ---- Threat markers ---- */
        const THREAT_POINTS = [
            { lat: 51.5,  lon: -0.1,   type: 'danger' },  // London
            { lat: 40.7,  lon: -74.0,  type: 'danger' },  // New York
            { lat: 35.7,  lon: 139.7,  type: 'warn'   },  // Tokyo
            { lat: 55.7,  lon: 37.6,   type: 'danger' },  // Moscow
            { lat: 31.2,  lon: 121.5,  type: 'danger' },  // Shanghai
            { lat: 48.9,  lon: 2.35,   type: 'safe'   },  // Paris
            { lat: 19.1,  lon: 72.9,   type: 'warn'   },  // Mumbai
            { lat: -23.5, lon: -46.6,  type: 'safe'   },  // São Paulo
            { lat: 1.35,  lon: 103.8,  type: 'warn'   },  // Singapore
            { lat: 33.9,  lon: -6.9,   type: 'danger' },  // Casablanca
            { lat: -33.8, lon: 151.2,  type: 'safe'   },  // Sydney
            { lat: 59.9,  lon: 10.7,   type: 'safe'   },  // Oslo
            { lat: 25.2,  lon: 55.3,   type: 'warn'   },  // Dubai
            { lat: 39.9,  lon: 116.4,  type: 'danger' },  // Beijing
            { lat: 52.5,  lon: 13.4,   type: 'safe'   },  // Berlin
        ];

        const markerGroup = new THREE.Group();
        scene.add(markerGroup);

        const colDanger = new THREE.Color(0xef4444);
        const colWarn   = new THREE.Color(0xf59e0b);
        const colSafe   = new THREE.Color(0x10b981);

        const markers = [];

        THREAT_POINTS.forEach(pt => {
            const phi   = (90 - pt.lat) * (Math.PI / 180);
            const theta = (pt.lon + 180) * (Math.PI / 180);
            const r = 1.015;

            const x = r * Math.sin(phi) * Math.cos(theta);
            const y = r * Math.cos(phi);
            const z = r * Math.sin(phi) * Math.sin(theta);

            const col = pt.type === 'danger' ? colDanger : pt.type === 'warn' ? colWarn : colSafe;

            /* Core dot */
            const dotGeo = new THREE.SphereGeometry(0.018, 8, 8);
            const dotMat = new THREE.MeshBasicMaterial({ color: col });
            const dot = new THREE.Mesh(dotGeo, dotMat);
            dot.position.set(x, y, z);
            markerGroup.add(dot);

            /* Pulse ring (flat torus) */
            const pulseGeo = new THREE.TorusGeometry(0.04, 0.007, 4, 24);
            const pulseMat = new THREE.MeshBasicMaterial({ color: col, transparent: true, opacity: 0.7 });
            const pulse = new THREE.Mesh(pulseGeo, pulseMat);
            pulse.position.set(x, y, z);

            /* Orient pulse ring to face outward from globe centre */
            pulse.lookAt(0, 0, 0);
            pulse.rotateX(Math.PI / 2);
            markerGroup.add(pulse);

            markers.push({ pulse, pulseMat, phase: Math.random() * Math.PI * 2 });
        });

        /* Arc connections between some threat nodes */
        function addArc(p1idx, p2idx) {
            const a = THREAT_POINTS[p1idx], b = THREAT_POINTS[p2idx];
            const toVec = (pt) => {
                const phi   = (90 - pt.lat) * (Math.PI / 180);
                const theta = (pt.lon + 180) * (Math.PI / 180);
                return new THREE.Vector3(
                    Math.sin(phi) * Math.cos(theta),
                    Math.cos(phi),
                    Math.sin(phi) * Math.sin(theta)
                );
            };
            const v1 = toVec(a), v2 = toVec(b);
            const pts = [];
            const MID_HEIGHT = 1.45;
            for (let i = 0; i <= 24; i++) {
                const t = i / 24;
                const lerped = new THREE.Vector3().lerpVectors(v1, v2, t);
                const h = MID_HEIGHT * Math.sin(t * Math.PI);
                lerped.normalize().multiplyScalar(1 + h * 0.45);
                pts.push(lerped);
            }
            const arcGeo = new THREE.BufferGeometry().setFromPoints(pts);
            const arcMat = new THREE.LineBasicMaterial({ color: 0xef4444, transparent: true, opacity: 0.35 });
            markerGroup.add(new THREE.Line(arcGeo, arcMat));
        }

        addArc(0, 1); addArc(4, 8); addArc(3, 13); addArc(1, 9); addArc(7, 5);

        /* Mouse drag rotation */
        let isDragging = false, prevMX = 0, prevMY = 0;
        let autoRot = true;
        let rotY = 0, rotX = 0.15;

        canvas.addEventListener('mousedown', (e) => { isDragging = true; prevMX = e.clientX; prevMY = e.clientY; autoRot = false; });
        window.addEventListener('mouseup', () => { isDragging = false; });
        window.addEventListener('mousemove', (e) => {
            if (!isDragging) return;
            rotY += (e.clientX - prevMX) * 0.008;
            rotX += (e.clientY - prevMY) * 0.008;
            rotX = Math.max(-1.2, Math.min(1.2, rotX));
            prevMX = e.clientX; prevMY = e.clientY;
        });

        /* Touch support */
        canvas.addEventListener('touchstart', (e) => { isDragging = true; prevMX = e.touches[0].clientX; prevMY = e.touches[0].clientY; autoRot = false; });
        canvas.addEventListener('touchend', () => { isDragging = false; });
        canvas.addEventListener('touchmove', (e) => {
            if (!isDragging) return;
            rotY += (e.touches[0].clientX - prevMX) * 0.008;
            rotX += (e.touches[0].clientY - prevMY) * 0.008;
            prevMX = e.touches[0].clientX; prevMY = e.touches[0].clientY;
        });

        let t = 0;
        function animate() {
            requestAnimationFrame(animate);
            t += 0.016;

            if (autoRot) rotY += 0.003;

            globe.rotation.y     = rotY;
            globe.rotation.x     = rotX;
            gridGroup.rotation.y = rotY;
            gridGroup.rotation.x = rotX;
            markerGroup.rotation.y = rotY;
            markerGroup.rotation.x = rotX;

            ring.rotation.z = t * 0.2;

            /* Pulse animation on markers */
            markers.forEach(m => {
                const scale = 1 + 0.6 * Math.abs(Math.sin(t * 1.8 + m.phase));
                m.pulse.scale.set(scale, scale, scale);
                m.pulseMat.opacity = 0.7 * (1 - Math.abs(Math.sin(t * 1.8 + m.phase)));
            });

            renderer.render(scene, camera);
        }
        animate();

        const ro = new ResizeObserver(() => {
            const pw = canvas.parentElement.clientWidth || 420;
            const ph = canvas.parentElement.clientHeight || 420;
            camera.aspect = pw / ph;
            camera.updateProjectionMatrix();
            renderer.setSize(pw, ph);
        });
        ro.observe(canvas.parentElement);
    }

    /* =========================================================
     * 3. NETWORK TOPOLOGY SCENE — 3D node graph
     * ========================================================= */
    function initNetworkTopology() {
        const canvas = document.getElementById('topology-canvas');
        if (!canvas) return;

        const W = canvas.parentElement.clientWidth  || 560;
        const H = canvas.parentElement.clientHeight || 320;

        const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
        renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
        renderer.setSize(W, H);

        const scene = new THREE.Scene();
        const camera = new THREE.PerspectiveCamera(55, W / H, 0.1, 200);
        camera.position.set(0, 0, 18);

        scene.add(new THREE.AmbientLight(0xffffff, 0.6));
        const pl = new THREE.PointLight(0x06b6d4, 2, 60);
        pl.position.set(0, 8, 8);
        scene.add(pl);

        /* --- Nodes --- */
        const NODE_COUNT = 20;
        const nodes = [];
        const nodeGroup = new THREE.Group();
        scene.add(nodeGroup);

        const nodeTypes = ['safe', 'danger', 'warn', 'safe', 'safe', 'danger', 'warn'];

        for (let i = 0; i < NODE_COUNT; i++) {
            const type = nodeTypes[Math.floor(Math.random() * nodeTypes.length)];
            const col = type === 'danger' ? 0xef4444 : type === 'warn' ? 0xf59e0b : 0x10b981;
            const size = type === 'danger' ? 0.28 : type === 'warn' ? 0.22 : 0.18;

            const geo = new THREE.SphereGeometry(size, 12, 12);
            const mat = new THREE.MeshPhongMaterial({
                color:    col,
                emissive: col,
                emissiveIntensity: 0.4,
                shininess: 60,
            });
            const mesh = new THREE.Mesh(geo, mat);

            const x = rand(-8, 8), y = rand(-4, 4), z = rand(-3, 3);
            mesh.position.set(x, y, z);
            nodeGroup.add(mesh);

            /* Glow ring around important nodes */
            if (type === 'danger') {
                const rGeo = new THREE.TorusGeometry(size + 0.12, 0.03, 6, 24);
                const rMat = new THREE.MeshBasicMaterial({ color: 0xef4444, transparent: true, opacity: 0.5 });
                const ring = new THREE.Mesh(rGeo, rMat);
                ring.position.copy(mesh.position);
                nodeGroup.add(ring);
            }

            nodes.push({
                mesh,
                type,
                velocity: new THREE.Vector3(rand(-0.008, 0.008), rand(-0.008, 0.008), rand(-0.004, 0.004)),
                phase: Math.random() * Math.PI * 2,
            });
        }

        /* --- Edges --- */
        const edgeGroup = new THREE.Group();
        scene.add(edgeGroup);
        const EDGE_THRESH = 7;

        function rebuildEdges() {
            while (edgeGroup.children.length) edgeGroup.remove(edgeGroup.children[0]);
            for (let i = 0; i < nodes.length; i++) {
                for (let j = i + 1; j < nodes.length; j++) {
                    const dist = nodes[i].mesh.position.distanceTo(nodes[j].mesh.position);
                    if (dist < EDGE_THRESH) {
                        const alpha = 0.12 * (1 - dist / EDGE_THRESH);
                        const edgeMat = new THREE.LineBasicMaterial({
                            color: 0x3b82f6,
                            transparent: true,
                            opacity: alpha,
                        });
                        const geo = new THREE.BufferGeometry().setFromPoints([
                            nodes[i].mesh.position.clone(),
                            nodes[j].mesh.position.clone(),
                        ]);
                        edgeGroup.add(new THREE.Line(geo, edgeMat));
                    }
                }
            }
        }

        /* Raycaster for hover */
        const raycaster = new THREE.Raycaster();
        const mouse = new THREE.Vector2();
        let hoveredNode = null;

        canvas.addEventListener('mousemove', (e) => {
            const rect = canvas.getBoundingClientRect();
            mouse.x = ((e.clientX - rect.left) / rect.width)  * 2 - 1;
            mouse.y = -((e.clientY - rect.top)  / rect.height) * 2 + 1;
            raycaster.setFromCamera(mouse, camera);
            const hits = raycaster.intersectObjects(nodes.map(n => n.mesh));
            if (hits.length > 0) {
                hoveredNode = hits[0].object;
                canvas.style.cursor = 'pointer';
            } else {
                hoveredNode = null;
                canvas.style.cursor = 'default';
            }
        });

        let t = 0;
        const BOUNDS = { x: 9, y: 4.5, z: 4 };

        function animate() {
            requestAnimationFrame(animate);
            t += 0.016;

            nodeGroup.rotation.y = t * 0.06;

            nodes.forEach((n, i) => {
                /* Slight float motion */
                n.mesh.position.x += n.velocity.x;
                n.mesh.position.y += n.velocity.y;
                n.mesh.position.z += n.velocity.z;

                /* Bounce off boundaries */
                ['x', 'y', 'z'].forEach(ax => {
                    const bnd = BOUNDS[ax];
                    if (Math.abs(n.mesh.position[ax]) > bnd) {
                        n.velocity[ax] *= -1;
                        n.mesh.position[ax] = Math.sign(n.mesh.position[ax]) * bnd;
                    }
                });

                /* Pulse scale for danger nodes */
                if (n.type === 'danger') {
                    const s = 1 + 0.2 * Math.sin(t * 2.5 + n.phase);
                    n.mesh.scale.set(s, s, s);
                }

                /* Hover enlarge */
                if (n.mesh === hoveredNode) {
                    n.mesh.scale.setScalar(1.6);
                }
            });

            /* Rebuild edges every ~30 frames for performance */
            if (Math.round(t * 60) % 30 === 0) rebuildEdges();

            renderer.render(scene, camera);
        }
        animate();

        /* Initial edge draw */
        rebuildEdges();

        const ro = new ResizeObserver(() => {
            const pw = canvas.parentElement.clientWidth || 560;
            const ph = canvas.parentElement.clientHeight || 320;
            camera.aspect = pw / ph;
            camera.updateProjectionMatrix();
            renderer.setSize(pw, ph);
        });
        ro.observe(canvas.parentElement);
    }

    /* =========================================================
     * 4. BOOT
     * ========================================================= */
    function boot() {
        if (typeof THREE === 'undefined') {
            console.warn('SecureNet 3D: Three.js not loaded yet, retrying...');
            setTimeout(boot, 200);
            return;
        }
        initBackground();
        initThreatGlobe();
        initNetworkTopology();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }

    /* Expose re-theming hook */
    window.SecureNet3D = { reTheme: boot };

})();
