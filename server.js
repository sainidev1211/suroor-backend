require('dotenv').config();
const express = require('express');
const cors = require('cors');
const ytSearch = require('yt-search');
const YTDlpWrap = require('yt-dlp-wrap').default;
const lyricsFinder = require('lyrics-finder');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3001;
const USERS_FILE = path.join(__dirname, 'data', 'users.json');
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_key_change_in_prod';

// --- DATABASE HELPERS ---
const getUsers = () => {
    try {
        if (!fs.existsSync(USERS_FILE)) return [];
        return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    } catch (e) { return []; }
};

const saveUsers = (users) => {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
};

// --- MIDDLEWARE ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ALLOWED ORIGINS (Local + GitHub Pages)
const allowedOrigins = [
    "http://localhost:5173",
    "https://sainidev1211.github.io"
];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(null, true); // Permissive for now to avoid mobile/other issues, or strict: callback(new Error('Not allowed by CORS'))
        }
    },
    credentials: true
}));

// --- JWT MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) return res.status(401).send("Access Denied");

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).send("Invalid Token");
        req.user = user;
        next();
    });
};

// Path for the binary
const ytDlpBinaryPath = path.join(__dirname, 'yt-dlp');

// Initializer: Check if binary exists, if not download it
(async () => {
    try {
        if (!fs.existsSync(ytDlpBinaryPath)) {
            console.log('[Init] Downloading yt-dlp binary...');
            await YTDlpWrap.downloadFromGithub(ytDlpBinaryPath);
            console.log('[Init] Downloaded yt-dlp binary.');
        } else {
            console.log('[Init] yt-dlp binary found.');
        }
    } catch (err) {
        console.error('[Init] Failed to download or verify yt-dlp binary:', err);
    }
})();

const ytDlp = new YTDlpWrap(ytDlpBinaryPath);

// --- AUTH ROUTES ---

// 1. SIGNUP
app.post('/auth/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!email || !password || !name) return res.status(400).send("Missing fields");

        const users = getUsers();
        if (users.find(u => u.email === email)) {
            return res.status(400).send("User already exists");
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = {
            id: 'user_' + Date.now(),
            name,
            email,
            password: hashedPassword,
            premium: true, // Auto-grant premium
            avatar: `https://ui-avatars.com/api/?name=${encodeURIComponent(name)}&background=ffbe0b&color=000`,
            likedSongs: [],
            playlists: [],
            history: []
        };

        users.push(newUser);
        saveUsers(users);

        // Sign Token
        const token = jwt.sign({ id: newUser.id, email: newUser.email }, JWT_SECRET, { expiresIn: '30d' });

        // Remove password from response
        const { password: _, ...userWithoutPass } = newUser;

        res.json({ user: userWithoutPass, token });
    } catch (e) {
        console.error(e);
        res.status(500).send("Signup failed");
    }
});

// 2. LOGIN
app.post('/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const users = getUsers();
        const user = users.find(u => u.email === email);

        if (!user) return res.status(400).send("User not found");

        if (await bcrypt.compare(password, user.password || "")) {
            // Success
            const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
            const { password: _, ...userWithoutPass } = user;
            res.json({ user: userWithoutPass, token });
        } else {
            res.status(400).send("Invalid credentials");
        }
    } catch (e) {
        res.status(500).send("Login failed");
    }
});

// 3. GET USER
app.get('/api/user', authenticateToken, (req, res) => {
    const users = getUsers();
    const user = users.find(u => u.id === req.user.id);
    if (!user) return res.status(404).send("User not found");
    const { password: _, ...userWithoutPass } = user;
    res.json(userWithoutPass);
});

// --- USER DATA ROUTES ---

app.post('/api/user/like', authenticateToken, (req, res) => {
    const { track } = req.body;
    if (!track) return res.status(400).send("No track provided");

    const users = getUsers();
    const userIndex = users.findIndex(u => u.id === req.user.id);

    if (userIndex !== -1) {
        let user = users[userIndex];
        const exists = user.likedSongs.find(t => t.id === track.id);

        if (exists) {
            user.likedSongs = user.likedSongs.filter(t => t.id !== track.id);
        } else {
            user.likedSongs.unshift(track);
        }

        users[userIndex] = user;
        saveUsers(users);
        res.json({ success: true, likedSongs: user.likedSongs });
    } else {
        res.status(404).send("User not found");
    }
});

// --- PLAYLIST ROUTES ---

app.post('/api/playlists', authenticateToken, (req, res) => {
    const { name } = req.body;
    const users = getUsers();
    const userIndex = users.findIndex(u => u.id === req.user.id);

    const newPlaylist = {
        id: Date.now(),
        name,
        created_at: new Date().toISOString(),
        songs: []
    };

    if (!users[userIndex].playlists) users[userIndex].playlists = [];
    users[userIndex].playlists.push(newPlaylist);
    saveUsers(users);

    res.json(newPlaylist);
});

app.post('/api/playlists/:id/add', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { track } = req.body;
    const users = getUsers();
    const userIndex = users.findIndex(u => u.id === req.user.id);

    const playlist = users[userIndex].playlists.find(p => p.id == id);
    if (!playlist) return res.status(404).send("Playlist not found");

    if (!playlist.songs.find(s => s.id === track.id)) {
        playlist.songs.push(track);
        saveUsers(users);
    }
    res.json(playlist);
});

// --- ADMIN ROUTES ---
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'suroor_admin_2025';

// Admin Middleware
const isAdmin = (req, res, next) => {
    const key = req.headers['x-admin-secret'];
    if (key === ADMIN_SECRET) {
        next();
    } else {
        res.status(403).send("Unauthorized Admin Access");
    }
};

app.get('/api/admin/stats', isAdmin, (req, res) => {
    const users = getUsers();
    const totalPlaylists = users.reduce((acc, u) => acc + (u.playlists ? u.playlists.length : 0), 0);
    const totalLiked = users.reduce((acc, u) => acc + (u.likedSongs ? u.likedSongs.length : 0), 0);

    const sensitiveUsers = users.map(u => ({
        id: u.id,
        name: u.name,
        email: u.email,
        joined: u.id.split('_')[1] ? new Date(parseInt(u.id.split('_')[1])).toISOString().split('T')[0] : 'Unknown'
    }));

    res.json({
        totalUsers: users.length,
        totalPlaylists,
        totalLiked,
        users: sensitiveUsers.reverse().slice(0, 50) // Last 50 users
    });
});

// --- PUBLIC ENDPOINTS (Search, Stream, Lyrics) ---

// LYRICS
app.get('/lyrics', async (req, res) => {
    const { artist, title } = req.query;
    if (!artist || !title) return res.status(400).send("Missing artist or title");

    try {
        const cleanTitle = title
            .replace(/\(.*\)/g, "")
            .replace(/\[.*\]/g, "")
            .replace(/official video|official audio|lyrics|live|hd|hq/gi, "")
            .replace(/ft\.|feat\./gi, "")
            .trim();

        const lyrics = await lyricsFinder(artist, cleanTitle) || await lyricsFinder(artist, title) || "Lyrics not found.";
        res.json({ lyrics });
    } catch (e) {
        res.status(500).send("Error fetching lyrics");
    }
});

// SEARCH
app.get('/search', async (req, res) => {
    try {
        const { query, type } = req.query;
        if (!query) return res.status(400).send("Query required");

        let searchTerm = query;
        if (type === 'music') searchTerm += " official audio music";
        else if (type === 'podcast') searchTerm += " full podcast episode interview";
        else if (type === 'stories') searchTerm += " audio story";
        else if (type === 'horror') searchTerm += " horror story audio";
        else if (type === 'crime') searchTerm += " crime story audio";

        const r = await ytSearch(searchTerm);
        let videos = r.videos.map(v => ({
            id: v.videoId,
            title: v.title,
            artist: v.author.name,
            cover: v.thumbnail,
            duration: v.timestamp,
            seconds: v.seconds
        }));

        res.json(videos.slice(0, 15));
    } catch (e) {
        console.error(e);
        res.json([]);
    }
});

// STREAM CACHE
const streamCache = new Map();
const CACHE_TTL_MS = 3600 * 1000;

// STREAM with JSON Support
app.get('/stream', async (req, res) => {
    try {
        const { query, json } = req.query;
        // Check Cache
        if (streamCache.has(query)) {
            const cached = streamCache.get(query);
            if (Date.now() < cached.expiry) {
                if (json === 'true') return res.json({ url: cached.url });
                return res.redirect(cached.url);
            }
        }

        const binaryPath = ytDlp.getBinaryPath() || './yt-dlp';
        const { exec } = require('child_process');

        let targetUrl = `https://www.youtube.com/watch?v=${query}`;
        // If not ID, search first (simplified here, assuming ID passed mostly from frontend)

        const command = `"${binaryPath}" -g -f "bestaudio/best" --no-check-certificate --force-ipv4 "${targetUrl}"`;

        exec(command, (error, stdout, stderr) => {
            if (error) {
                console.error(`yt-dlp error: ${stderr}`);
                return res.status(500).send('Stream error');
            }
            const directUrl = stdout.trim();

            streamCache.set(query, { url: directUrl, expiry: Date.now() + CACHE_TTL_MS });

            if (json === 'true') {
                return res.json({ url: directUrl });
            } else {
                return res.redirect(directUrl);
            }
        });
    } catch (e) {
        res.status(500).send(e.message);
    }
});

// Start Server
const server = app.listen(PORT, () => {
    console.log(`Backend running on port ${PORT}`);
});

// GLOBAL ERROR HANDLERS
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    // Application specific logging, throwing an error, or other logic here
});

process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception thrown:', err);
    // process.exit(1); // Optional: restart via PM2 or Render
});
