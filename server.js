const express = require('express');
const path = require('path');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const config = require('./config.json');
const axios = require('axios');


const app = express();
const PORT = 20568;
// Add this near the top with your other constants
const rankHierarchy = {
    'default': 0,
    'mod': 1,
    'srmod': 2,
    'admin': 3,
    'headadmin': 4,
    'manager': 5,
    'owner': 6
};
const dbPool = mysql.createPool({
    host: config.DB_HOST,
    port: config.DB_PORT,
    user: config.DB_USER,
    password: config.DB_PASSWORD,
    database: config.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});
// --- NEW: Session Store Setup ---
const sessionStore = new MySQLStore({
    // Options for the session store
    clearExpired: true, // Automatically remove expired sessions
    checkExpirationInterval: 900000, // How often to check for expired sessions (15 minutes)
    expiration: 86400000, // The maximum age of a session (24 hours)
    createDatabaseTable: true, // Automatically create the sessions table
    schema: {
        tableName: 'web_sessions',
        columnNames: {
            session_id: 'session_id',
            expires: 'expires',
            data: 'data'
        }
    }
}, dbPool); // Use your existing database connection pool

// --- Session Middleware Setup ---
app.use(session({
    secret: 'a-very-secret-key-that-you-should-change',
    resave: false,
    saveUninitialized: true,
    store: sessionStore, // <-- Tell session to use the database store
    cookie: { 
        secure: false, // Set to true if using HTTPS
        maxAge: 86400000 // Cookie lifetime should match session expiration
    }
}));


// --- General Middleware ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));


// --- Helper Functions ---
async function sendSyncCommand() {
    try {
        console.log('[Plugin] Sending sync request to the game server...');
        await axios.post(config.PLUGIN_SYNC_URL, {
            secretKey: config.PLUGIN_SECRET_KEY
        });
        console.log('[Plugin] Sync request sent successfully.');
    } catch (error) {
        console.error('[Plugin] Failed to send sync request:', error.message);
    }
}
// Middleware to check if a user is logged in (for protecting sensitive APIs)
const isAuthenticated = (req, res, next) => {
    if (req.session.user) {
        return next();
    }
    res.status(401).json({ error: 'Not authenticated' }); // Send error for API calls
};
const isStaff = (req, res, next) => {
    if (req.session.user) {
        // Define which ranks can access staff pages
        const staffRanks = ['mod', 'srmod', 'admin', 'headadmin', 'manager', 'owner'];
        if (staffRanks.includes(req.session.user.primary_group)) {
            return next(); // User is staff, proceed
        }
    }
    res.status(404).sendFile(path.join(__dirname, 'public', 'html', '404.html'));
};
// NEW: Middleware for Admin and above
const isAdmin = (req, res, next) => {
    if (req.session.user) {
        const adminRanks = ['admin', 'headadmin', 'manager', 'owner'];
        if (adminRanks.includes(req.session.user.primary_group)) {
            return next(); // User is an admin or higher, proceed
        }
    }
    // If not admin, send a 404 error
    res.status(404).sendFile(path.join(__dirname, 'public', 'html', '404.html'));
};
// Add this to your Page Routes section
app.get('/staff/management', isAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'html', 'staff-management.html'));
});

// Add this to your API Endpoints section
app.get('/api/all-staff', isAdmin, async (req, res) => {
    try {
        res.setHeader('Cache-Control', 'no-store');

        const staffRanks = ['mod', 'srmod'];

        // ✅ Dynamically create placeholders (?, ?)
        const placeholders = staffRanks.map(() => '?').join(',');

        // ✅ Inject the placeholders directly into the SQL string
        const query = `
            SELECT 
                lp.username, 
                lp.primary_group, 
                lp.uuid,
                lgp.permission AS suffix_permission
            FROM luckperms_players AS lp
            LEFT JOIN luckperms_group_permissions AS lgp 
                ON lp.primary_group = lgp.name 
                AND lgp.permission LIKE 'suffix.%'
            WHERE lp.primary_group IN (${placeholders})
        `;

        // ✅ Pass the array directly, NOT nested
        const [rows] = await dbPool.execute(query, staffRanks);

        // ✅ Process suffix to extract color style
        const staffWithColors = rows.map(staff => {
            const { style } = staff.suffix_permission
                ? parseMinecraftColors(staff.suffix_permission)
                : { style: '' };
            return { ...staff, colorStyle: style };
        });

        res.json(staffWithColors);

    } catch (dbError) {
        console.error('Database query error (all-staff):', dbError);
        res.status(500).json({ error: 'Failed to fetch staff list.' });
    }
});
// API to WARN a staff member
app.post('/api/staff/warn', isAdmin, async (req, res) => {
    const { username, reason } = req.body;
    if (!username || !reason) {
        return res.status(400).json({ success: false, message: 'Username and reason are required.' });
    }
    try {
        await dbPool.execute(
            'INSERT INTO `staff_warnings` (username, reason, created_at) VALUES (?, ?, NOW())',
            [username, reason]
        );
        res.json({ success: true, message: 'Staff member has been warned.' });
    } catch (dbError) {
        res.status(500).json({ success: false, message: 'Failed to issue warning.' });
    }
});

// API to PROMOTE a staff member
// API to PROMOTE a staff member with permission checks
app.post('/api/staff/promote', isAdmin, async (req, res) => {
    const { username, newRank } = req.body;
    const adminUsername = req.session.user.username;

    try {
        // Get ranks of both the admin and the target user
        const [users] = await dbPool.execute(
            'SELECT username, primary_group FROM `luckperms_players` WHERE username IN (?, ?)',
            [[adminUsername, username]]
        );
        
        const adminUser = users.find(u => u.username === adminUsername);
        const targetUser = users.find(u => u.username === username);

        if (!adminUser || !targetUser) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        const adminRankLevel = rankHierarchy[adminUser.primary_group] || 0;
        const targetRankLevel = rankHierarchy[targetUser.primary_group] || 0;
        const newRankLevel = rankHierarchy[newRank] || 0;

        // SECURITY CHECK: Admin must have a higher rank than the target and the new rank
        if (adminRankLevel > targetRankLevel && adminRankLevel >= newRankLevel) {
            await dbPool.execute(
                'UPDATE `luckperms_players` SET primary_group = ? WHERE username = ?',
                [newRank, username]
            );
            await sendSyncCommand();
            res.json({ success: true, message: `${username} has been promoted to ${newRank}.` });
        } else {
            res.status(403).json({ success: false, message: 'You do not have permission to perform this promotion.' });
        }
    } catch (dbError) {
        res.status(500).json({ success: false, message: 'Failed to promote staff.' });
    }
});

// API to DEMOTE a staff member with permission checks
app.post('/api/staff/demote', isAdmin, async (req, res) => {
    const { username, newRank } = req.body;
    const adminUsername = req.session.user.username;

    try {
        const [users] = await dbPool.execute(
            'SELECT username, primary_group FROM `luckperms_players` WHERE username IN (?, ?)',
            [[adminUsername, username]]
        );

        const adminUser = users.find(u => u.username === adminUsername);
        const targetUser = users.find(u => u.username === username);

        if (!adminUser || !targetUser) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        const adminRankLevel = rankHierarchy[adminUser.primary_group] || 0;
        const targetRankLevel = rankHierarchy[targetUser.primary_group] || 0;

        // SECURITY CHECK: Admin must have a higher rank than the target
        if (adminRankLevel > targetRankLevel) {
            await dbPool.execute(
                'UPDATE `luckperms_players` SET primary_group = ? WHERE username = ?',
                [newRank, username]
            );
            await sendSyncCommand();
            res.json({ success: true, message: `${username} has been demoted to ${newRank}.` });
        } else {
            res.status(403).json({ success: false, message: 'You do not have permission to perform this demotion.' });
        }
    } catch (dbError) {
        res.status(500).json({ success: false, message: 'Failed to demote staff.' });
    }
});
app.get('/staff/management/:username', isAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'html', 'manage-staff.html'));
});
// Add this to your API Endpoints section
app.post('/api/staff/setrank', isAdmin, async (req, res) => {
    const { username, newRank } = req.body;
    // Define the ranks that can be assigned this way
    const assignableRanks = ['mod', 'srmod', 'admin', 'headadmin', 'manager'];

    if (!username || !assignableRanks.includes(newRank)) {
        return res.status(400).json({ success: false, message: 'Invalid username or rank provided.' });
    }
    try {
        // This query updates the player's group. It works even if they are currently 'default'.
        const [result] = await dbPool.execute(
            'UPDATE `luckperms_players` SET primary_group = ? WHERE username = ?',
            [newRank, username]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: `Player '${username}' not found in LuckPerms.` });
        }

        await sendSyncCommand(); // Sync changes with the game server
        
        res.json({ success: true, message: `${username}'s rank has been set to ${newRank}.` });
    } catch (dbError) {
        console.error('Database query error (set rank):', dbError);
        res.status(500).json({ success: false, message: 'Failed to set player rank.' });
    }
});
// NEW: Middleware for Senior Staff and above
const isSeniorStaff = (req, res, next) => {
    if (req.session.user) {
        const seniorStaffRanks = ['srmod', 'admin', 'headadmin', 'manager', 'owner'];
        if (seniorStaffRanks.includes(req.session.user.primary_group)) {
            return next(); // User is senior staff, proceed
        }
    }
    res.status(404).sendFile(path.join(__dirname, 'public', 'html', '404.html'));
};
app.get('/staff/muted-words', isSeniorStaff, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'html', 'muted-words.html'));
});
app.get('/api/pending-words', isSeniorStaff, async (req, res) => {
    try {
        res.setHeader('Cache-Control', 'no-store');
        const [rows] = await dbPool.execute(
            'SELECT id, word, created_at FROM `pending_words` ORDER BY id DESC'
        );
        res.json(rows);
    } catch (dbError) {
        res.status(500).json({ error: 'Failed to fetch pending words.' });
    }
});

// API to POST (save) reviewed words
// API to POST (save) reviewed words
app.post('/api/save-words', isSeniorStaff, async (req, res) => {
    const { wordsToSave, wordsToDelete } = req.body;
    const added_by = req.session.user.username;
    const connection = await dbPool.getConnection();

    try {
        await connection.beginTransaction();

        if (wordsToSave && wordsToSave.length > 0) {
            const insertPromises = wordsToSave.map(word => {
                const finalReason = word.note ? `${word.reason} | ${word.note}` : word.reason;
                
                // ✅ FIX: Reversed the logic. is_banned is true UNLESS the reason is "Allowed".
                const is_banned = word.reason !== "Allowed";

                return connection.execute(
                    'INSERT INTO `words` (word, added_by, reason, is_banned, last_edited) VALUES (?, ?, ?, ?, NOW())',
                    [word.word, added_by, finalReason, is_banned]
                );
            });
            await Promise.all(insertPromises);
        }
        
        const allIdsToDelete = [
            ...(wordsToSave || []).map(w => w.id),
            ...(wordsToDelete || [])
        ];

        if (allIdsToDelete.length > 0) {
            await connection.query(
                'DELETE FROM `pending_words` WHERE id IN (?)',
                [allIdsToDelete]
            );
        }

        await connection.commit();
        res.json({ success: true, message: 'Words saved successfully!' });

    } catch (error) {
        await connection.rollback();
        console.error('Error saving words:', error);
        res.status(500).json({ success: false, message: 'An error occurred.' });
    } finally {
        connection.release();
    }
});
app.get('/staff/all-words', isSeniorStaff, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'html', 'all-words.html'));
});
app.get('/api/all-words', isSeniorStaff, async (req, res) => {
    try {
        res.setHeader('Cache-Control', 'no-store');
        const [rows] = await dbPool.execute(`
            SELECT 
                w.id, w.word, w.added_by, w.reason, w.last_edited,
                lp.uuid AS added_by_uuid,
                lgp.permission AS suffix_permission
            FROM \`words\` AS w
            LEFT JOIN \`luckperms_players\` AS lp ON w.added_by = lp.username
            LEFT JOIN \`luckperms_group_permissions\` AS lgp ON lp.primary_group = lgp.name AND lgp.permission LIKE 'suffix.%'
            ORDER BY w.id DESC
        `);
        
        const wordsWithColors = rows.map(word => {
            const { style } = word.suffix_permission ? parseMinecraftColors(word.suffix_permission) : { style: '' };
            return { ...word, added_by_color_style: style };
        });

        res.json(wordsWithColors);
    } catch (dbError) {
        console.error('Database query error (all-words):', dbError);
        res.status(500).json({ error: 'Failed to fetch words.' });
    }
});
// Minecraft Color Code Parser
function parseMinecraftColors(permissionString) {
    const colorMap = {
        '&0': '#000000', '&1': '#0000AA', '&2': '#00AA00', '&3': '#00AAAA',
        '&4': '#AA0000', '&5': '#AA00AA', '&6': '#FFAA00', '&7': '#AAAAAA',
        '&8': '#555555', '&9': '#5555FF', '&a': '#55FF55', '&b': '#55FFFF',
        '&c': '#FF5555', '&d': '#FF55FF', '&e': '#FFFF55', '&f': '#FFFFFF'
    };
    let style = '';
    let primaryColor = null;
    const colorCodes = permissionString.match(/&[0-9a-fk-or]/g) || [];
    
    colorCodes.forEach(code => {
        if (colorMap[code]) {
            if (!primaryColor) primaryColor = colorMap[code];
            style += `color: ${colorMap[code]};`;
        }
        if (code === '&l') style += 'font-weight: bold;';
        if (code === '&o') style += 'font-style: italic;';
        if (code === '&n') style += 'text-decoration: underline;';
        if (code === '&m') style += 'text-decoration: line-through;';
    });
    return { style, hexColor: primaryColor };
}


// --- Page Routes (Publicly Accessible) ---

// The root now serves the HOME page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'html', 'home.html'));
});

// Route for the login page
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'html', 'login.html'));
});

// Route for the players page
app.get('/players', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'html', 'players.html'));
});

// Route for the profile page
app.get('/profile/:username', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'html', 'profile.html'));
});

app.get('/staff/home', isStaff, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'html', 'my-stats.html'));
});
app.get('/api/my-stats', isAuthenticated, async (req, res) => {
    try {
        const username = req.session.user.username;
        res.setHeader('Cache-Control', 'no-store');

        // The query now also selects banCounts and muteCounts
        const sql = `
            SELECT
                lp.username, lp.primary_group, lp.uuid,
                db.playtime,
                db.banCounts,
                db.muteCounts,
                pvp.points, pvp.kills, pvp.deaths, pvp.shards
            FROM luckperms_players AS lp
            LEFT JOIN deepbungee AS db ON lp.uuid = db.uuid
            LEFT JOIN pvp_nullping AS pvp ON lp.uuid = pvp.uuid
            WHERE lp.username = ?
        `;

        const [rows] = await dbPool.execute(sql, [username]);

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Player stats not found' });
        }

        res.json(rows[0]);

    } catch (dbError) {
        console.error('Database query error (my-stats):', dbError);
        res.status(500).json({ error: 'Failed to fetch your stats.' });
    }
});
// UPDATED: API endpoint to check words and add them if not found
app.post('/api/check-word', isAuthenticated, async (req, res) => {
    try {
        const { word } = req.body;
        const checked_by = req.session.user.username; // Get the staff member's name

        if (!word) {
            return res.status(400).json({ error: 'Word is required.' });
        }

        // Check if the word exists in the main 'words' table
        const [rows] = await dbPool.execute(
            'SELECT reason, is_banned FROM `words` WHERE word = ?',
            [word]
        );

        if (rows.length > 0) {
            if (rows[0].is_banned) {
                return res.json({ found: true, allowed: false, reason: rows[0].reason });
            } else {
                return res.json({ found: true, allowed: true, message: `Word '${word}' is allowed.` });
            }
        }

        // If the word does not exist, add it to pending_words
        // ✅ FIX: Provide the 'checked_by' value in the query
        await dbPool.execute(
            'INSERT INTO `pending_words` (word, checked_by, created_at) VALUES (?, ?, NOW()) ON DUPLICATE KEY UPDATE word=word',
            [word, checked_by]
        );

        res.json({ found: false, message: `Word '${word}' submitted for review.` });

    } catch (dbError) {
        console.error('Database query error (check-word):', dbError);
        res.status(500).json({ error: 'Failed to process word.' });
    }
});
// Add this to your API Endpoints section
app.get('/api/my-warnings', isAuthenticated, async (req, res) => {
    try {
        const username = req.session.user.username;
        res.setHeader('Cache-Control', 'no-store');

        const [rows] = await dbPool.execute(
            'SELECT reason, created_at FROM `staff_warnings` WHERE username = ? ORDER BY id DESC',
            [username]
        );
        res.json(rows);

    } catch (dbError) {
        console.error('Database query error (my-warnings):', dbError);
        res.status(500).json({ error: 'Failed to fetch your warnings.' });
    }
});
app.get('/staff/my-bans', isStaff, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'html', 'my-bans.html'));
});
app.get('/api/my-bans', isStaff, async (req, res) => {
    try {
        const adminUsername = req.session.user.username;
        res.setHeader('Cache-Control', 'no-store');
        
        const sql = `
            SELECT 
                dp.banid, dp.ign, dp.banReason, dp.banDuration, dp.banExpiresAt,
                lp.primary_group,
                lgp.permission AS suffix_permission
            FROM deep_punishments AS dp
            LEFT JOIN luckperms_players AS lp ON dp.ign = lp.username
            LEFT JOIN luckperms_group_permissions AS lgp ON lp.primary_group = lgp.name AND lgp.permission LIKE 'suffix.%'
            WHERE dp.banBy = ?
            ORDER BY dp.banid DESC
        `;

        const [rows] = await dbPool.execute(sql, [adminUsername]);

        const bansWithColors = rows.map(ban => {
            const { style } = ban.suffix_permission ? parseMinecraftColors(ban.suffix_permission) : { style: '' };
            return { ...ban, colorStyle: style };
        });

        res.json(bansWithColors);
    } catch (dbError) {
        console.error('Database query error (my-bans):', dbError);
        res.status(500).json({ error: 'Failed to fetch your bans.' });
    }
});

app.get('/staff/top-bans', isStaff, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'html', 'top-bans.html'));
});
// Add this to your API Endpoints section
app.get('/api/top-bans', isStaff, async (req, res) => {
    try {
        res.setHeader('Cache-Control', 'no-store');
        const staffRanks = ['mod', 'srmod', 'admin', 'headadmin', 'manager', 'owner'];

        // Generate correct number of placeholders: ?, ?, ?, ...
        const placeholders = staffRanks.map(() => '?').join(',');

        const sql = `
            SELECT 
                db.ign,
                db.banCounts,
                lp.uuid,
                lgp.permission AS suffix_permission
            FROM deepbungee AS db
            JOIN luckperms_players AS lp ON db.ign = lp.username
            LEFT JOIN luckperms_group_permissions AS lgp ON lp.primary_group = lgp.name AND lgp.permission LIKE 'suffix.%'
            WHERE lp.primary_group IN (${placeholders}) AND db.banCounts > 0
            ORDER BY db.banCounts DESC
        `;

        const [rows] = await dbPool.execute(sql, staffRanks);

        const staffWithColors = rows.map(staff => {
            const { style } = staff.suffix_permission ? parseMinecraftColors(staff.suffix_permission) : { style: '' };
            return { ...staff, colorStyle: style };
        });

        res.json(staffWithColors);
    } catch (dbError) {
        console.error('Database query error (top-bans):', dbError);
        res.status(500).json({ error: 'Failed to fetch top bans.' });
    }
});
// Add this to your Page Routes section
app.get('/staff/appeals', isSeniorStaff, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'html', 'appeals.html'));
});
// Add this to your API Endpoints section
app.get('/api/appeals', isSeniorStaff, async (req, res) => {
    try {
        res.setHeader('Cache-Control', 'no-store');
        const sql = `
            SELECT 
                a.id, a.username, a.punishment_type, a.reason, a.created_at, a.status, a.handled_by,
                lp.uuid,
                lgp.permission AS suffix_permission
            FROM appeals AS a
            LEFT JOIN luckperms_players AS lp ON a.username = lp.username
            LEFT JOIN luckperms_group_permissions AS lgp ON lp.primary_group = lgp.name AND lgp.permission LIKE 'suffix.%'
            WHERE a.status = 'pending'
            ORDER BY a.id DESC
        `;
        const [rows] = await dbPool.execute(sql);

        const appealsWithColor = rows.map(appeal => {
            const { style } = appeal.suffix_permission ? parseMinecraftColors(appeal.suffix_permission) : { style: '' };
            return { ...appeal, colorStyle: style };
        });

        res.json(appealsWithColor);
    } catch (dbError) {
        console.error('Database query error (appeals):', dbError);
        res.status(500).json({ error: 'Failed to fetch appeals.' });
    }
});

app.get('/staff/active-bans', isSeniorStaff, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'html', 'active-bans.html'));
});
app.get('/staff/active-mutes', isSeniorStaff, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'html', 'active-mutes.html'));
});
app.get('/appeal', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'html', 'appeal.html'));
});
app.get('/report', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'html', 'report.html'));
});
app.get('/staff/admin-reports', isSeniorStaff, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'html', 'admin-reports.html'));
});
// Add this to your Page Routes section
app.get('/staff/reports-history', isSeniorStaff, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'html', 'reports-history.html'));
});
// Page route for viewing a single report
app.get('/staff/admin-reports/:report_id', isSeniorStaff, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'html', 'view-report.html'));
});
// Add this to your API Endpoints section
app.get('/api/reports-history', isSeniorStaff, async (req, res) => {
    try {
        res.setHeader('Cache-Control', 'no-store');
        const sql = `
            SELECT 
                rh.*,
                reporter_lp.uuid AS reporter_uuid,
                reporter_lgp.permission AS reporter_suffix,
                reported_lp.uuid AS reported_uuid,
                reported_lgp.permission AS reported_suffix,
                handler_lp.uuid AS handler_uuid,
                handler_lgp.permission AS handler_suffix
            FROM reports_history AS rh
            LEFT JOIN luckperms_players AS reporter_lp ON rh.reporter_username = reporter_lp.username
            LEFT JOIN luckperms_group_permissions AS reporter_lgp ON reporter_lp.primary_group = reporter_lgp.name AND reporter_lgp.permission LIKE 'suffix.%'
            LEFT JOIN luckperms_players AS reported_lp ON rh.reported_username = reported_lp.username
            LEFT JOIN luckperms_group_permissions AS reported_lgp ON reported_lp.primary_group = reported_lgp.name AND reported_lgp.permission LIKE 'suffix.%'
            LEFT JOIN luckperms_players AS handler_lp ON rh.handled_by = handler_lp.username
            LEFT JOIN luckperms_group_permissions AS handler_lgp ON handler_lp.primary_group = handler_lgp.name AND handler_lgp.permission LIKE 'suffix.%'
            ORDER BY rh.id DESC
        `;
        const [rows] = await dbPool.execute(sql);

        const historyWithColors = rows.map(row => {
            const { style: reporterStyle } = row.reporter_suffix ? parseMinecraftColors(row.reporter_suffix) : { style: '' };
            const { style: reportedStyle } = row.reported_suffix ? parseMinecraftColors(row.reported_suffix) : { style: '' };
            const { style: handlerStyle } = row.handler_suffix ? parseMinecraftColors(row.handler_suffix) : { style: '' };
            return { ...row, reporterStyle, reportedStyle, handlerStyle };
        });

        res.json(historyWithColors);
    } catch (dbError) {
        console.error('Database query error (reports-history):', dbError);
        res.status(500).json({ error: 'Failed to fetch reports history.' });
    }
});

// API endpoint to get details for a single report
app.get('/api/report/:id', isSeniorStaff, async (req, res) => {
    try {
        const reportId = req.params.id;
        // This query is very similar to the list one but for a single ID
        const sql = `
            SELECT 
                r.*,
                reporter_lp.primary_group AS reporter_group,
                reporter_lgp.permission AS reporter_suffix,
                reported_lp.primary_group AS reported_group,
                reported_lgp.permission AS reported_suffix
            FROM reports AS r
            LEFT JOIN luckperms_players AS reporter_lp ON r.reporter_username = reporter_lp.username
            LEFT JOIN luckperms_group_permissions AS reporter_lgp ON reporter_lp.primary_group = reporter_lgp.name AND reporter_lgp.permission LIKE 'suffix.%'
            LEFT JOIN luckperms_players AS reported_lp ON r.reported_username = reported_lp.username
            LEFT JOIN luckperms_group_permissions AS reported_lgp ON reported_lp.primary_group = reported_lgp.name AND reported_lgp.permission LIKE 'suffix.%'
            WHERE r.id = ?
        `;
        const [rows] = await dbPool.execute(sql, [reportId]);

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Report not found.' });
        }

        const report = rows[0];
        const { style: reporterStyle } = report.reporter_suffix ? parseMinecraftColors(report.reporter_suffix) : { style: '' };
        const { style: reportedStyle } = report.reported_suffix ? parseMinecraftColors(report.reported_suffix) : { style: '' };
        
        res.json({ ...report, reporterStyle, reportedStyle });

    } catch (dbError) {
        res.status(500).json({ error: 'Failed to fetch report details.' });
    }
});
// --- API Endpoints ---
app.get('/api/admin-reports', isSeniorStaff, async (req, res) => {
    try {
        const sql = `
            SELECT 
                r.id, r.reporter_username, r.reported_username, r.report_type, r.evidence_link, r.status, r.claimed_by,
                reporter_lp.primary_group AS reporter_group,
                reporter_lgp.permission AS reporter_suffix,
                reported_lp.primary_group AS reported_group,
                reported_lgp.permission AS reported_suffix
            FROM reports AS r
            LEFT JOIN luckperms_players AS reporter_lp ON r.reporter_username = reporter_lp.username
            LEFT JOIN luckperms_group_permissions AS reporter_lgp ON reporter_lp.primary_group = reporter_lgp.name AND reporter_lgp.permission LIKE 'suffix.%'
            LEFT JOIN luckperms_players AS reported_lp ON r.reported_username = reported_lp.username
            LEFT JOIN luckperms_group_permissions AS reported_lgp ON reported_lp.primary_group = reported_lgp.name AND reported_lgp.permission LIKE 'suffix.%'
            WHERE r.status IN ('pending', 'claimed') 
            ORDER BY r.id DESC
        `;
        const [rows] = await dbPool.execute(sql);

        const reportsWithColors = rows.map(report => {
            const { style: reporterStyle } = report.reporter_suffix ? parseMinecraftColors(report.reporter_suffix) : { style: '' };
            const { style: reportedStyle } = report.reported_suffix ? parseMinecraftColors(report.reported_suffix) : { style: '' };
            return { ...report, reporterStyle, reportedStyle };
        });

        res.json(reportsWithColors);
    } catch (dbError) {
        res.status(500).json({ error: 'Failed to fetch reports.' });
    }
});
// API to POST a claim on a report
app.post('/api/reports/claim/:id', isSeniorStaff, async (req, res) => {
    try {
        const reportId = req.params.id;
        const adminUsername = req.session.user.username;
        await dbPool.execute(
            "UPDATE `reports` SET status = 'claimed', claimed_by = ? WHERE id = ? AND status = 'pending'",
            [adminUsername, reportId]
        );
        res.json({ success: true });
    } catch (dbError) {
        res.status(500).json({ success: false, message: 'Failed to claim report.' });
    }
});
app.post('/api/submit-report', isAuthenticated, async (req, res) => {
    const { reported_username, report_type, evidence_link, extra_notes } = req.body;
    const reporter_username = req.session.user.username;

    if (!reported_username || !report_type || !evidence_link) {
        return res.status(400).json({ success: false, message: 'Please fill out all required fields.' });
    }
    try {
        await dbPool.execute(
            'INSERT INTO `reports` (reporter_username, reported_username, report_type, evidence_link, extra_notes) VALUES (?, ?, ?, ?, ?)',
            [reporter_username, reported_username, report_type, evidence_link, extra_notes]
        );
        res.json({ success: true, message: 'Your report has been submitted successfully. Thank you!' });
    } catch (dbError) {
        console.error("Error submitting report:", dbError);
        res.status(500).json({ success: false, message: 'Failed to submit report.' });
    }
});
// API to check for the user's most recent active punishment
// API to check for the user's active punishment AND any existing appeal
// API to check for the user's active punishment AND any existing appeal
app.get('/api/my-punishment', isAuthenticated, async (req, res) => {
    try {
        const userUUID = req.session.user.uuid;
        res.setHeader('Cache-Control', 'no-store');

        const [punishmentRows] = await dbPool.execute(
            `SELECT banid, banReason, banDuration, banExpiresAt, muteid, muteReason, muteDuration, muteExpiresAt 
             FROM \`deep_punishments\` 
             WHERE uuid = ? AND (
                (banExpiresAt = 0 OR banExpiresAt > UNIX_TIMESTAMP() * 1000) OR
                (muteExpiresAt = 0 OR muteExpiresAt > UNIX_TIMESTAMP() * 1000)
             )`, [userUUID]
        );

        const activeBan = punishmentRows.find(p => p.banid);
        const activeMute = punishmentRows.find(p => p.muteid);
        
        let appealData = null;
        if (activeBan || activeMute) {
            const punishment_id = activeBan ? activeBan.banid : activeMute.muteid;
            const punishment_type = activeBan ? 'ban' : 'mute';
            const [appealRows] = await dbPool.execute(
                'SELECT status, response FROM `appeals` WHERE punishment_id = ? AND punishment_type = ?',
                [punishment_id, punishment_type]
            );
            if (appealRows.length > 0) {
                appealData = appealRows[0];
            }
        }

        res.json({
            hasBan: !!activeBan,
            banDetails: activeBan,
            hasMute: !!activeMute,
            muteDetails: activeMute,
            appeal: appealData
        });
    } catch (dbError) {
        console.error('Database query error (my-punishment):', dbError);
        res.status(500).json({ error: 'Failed to fetch punishment status.' });
    }
});

// API to add/update a staff response to an appeal
app.post('/api/appeal/update-response/:id', isSeniorStaff, async (req, res) => {
    const appealId = req.params.id;
    const { response } = req.body;
    const handled_by = req.session.user.username;

    if (!response) {
        return res.status(400).json({ success: false, message: 'A response is required.' });
    }
    try {
        await dbPool.execute(
            "UPDATE `appeals` SET response = ?, handled_by = ? WHERE id = ?",
            [response, handled_by, appealId]
        );
        res.json({ success: true, message: 'Response has been updated.' });
    } catch (dbError) {
        res.status(500).json({ success: false, message: 'Failed to update appeal.' });
    }
});
// Add this to your API Endpoints section
app.post('/api/appeal/claim/:id', isSeniorStaff, async (req, res) => {
    const appealId = req.params.id;
    const handled_by = req.session.user.username;
    try {
        const [result] = await dbPool.execute(
            "UPDATE `appeals` SET status = 'claimed', handled_by = ? WHERE id = ? AND status = 'pending'",
            [handled_by, appealId]
        );

        if (result.affectedRows > 0) {
            res.json({ success: true, message: 'Appeal claimed successfully.' });
        } else {
            res.status(409).json({ success: false, message: 'This appeal has already been claimed.' });
        }
    } catch (dbError) {
        console.error('Database query error (claim appeal):', dbError);
        res.status(500).json({ success: false, message: 'Failed to claim appeal.' });
    }
});

// Add this to your Page Routes section
app.get('/staff/appeals/:id', isSeniorStaff, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'html', 'view-appeal.html'));
});
// API to get details for a single appeal
app.get('/api/appeal/:id', isSeniorStaff, async (req, res) => {
    try {
        const appealId = req.params.id;
        const sql = `
            SELECT 
                a.*,
                lp.uuid,
                lgp.permission AS suffix_permission,
                dp.banBy, dp.banReason, dp.muteBy, dp.muteReason
            FROM appeals AS a
            LEFT JOIN luckperms_players AS lp ON a.username = lp.username
            LEFT JOIN luckperms_group_permissions AS lgp ON lp.primary_group = lgp.name AND lgp.permission LIKE 'suffix.%'
            LEFT JOIN deep_punishments AS dp ON a.punishment_id = IF(a.punishment_type = 'ban', dp.banid, dp.muteid)
            WHERE a.id = ?
        `;
        const [rows] = await dbPool.execute(sql, [appealId]);

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Appeal not found.' });
        }
        
        const appeal = rows[0];
        const { style } = appeal.suffix_permission ? parseMinecraftColors(appeal.suffix_permission) : { style: '' };
        res.json({ ...appeal, colorStyle: style });

    } catch (dbError) {
        res.status(500).json({ error: 'Failed to fetch appeal details.' });
    }
});

// API to handle an appeal (accept/deny)
app.post('/api/appeal/handle/:id', isSeniorStaff, async (req, res) => {
    const appealId = req.params.id;
    const { outcome, punishment_id, punishment_type } = req.body;
    const handled_by = req.session.user.username;
    const connection = await dbPool.getConnection();

    try {
        await connection.beginTransaction();

        // Update the appeal status
        await connection.execute(
            "UPDATE `appeals` SET status = ?, handled_by = ? WHERE id = ?",
            [outcome, handled_by, appealId]
        );

        // If accepted, remove the original punishment
        if (outcome === 'Accepted') {
            if (punishment_type === 'ban') {
                await connection.execute("UPDATE `deep_punishments` SET banExpiresAt = 1 WHERE banid = ?", [punishment_id]);
            } else if (punishment_type === 'mute') {
                await connection.execute("UPDATE `deep_punishments` SET muteExpiresAt = 1 WHERE muteid = ?", [punishment_id]);
            }
        }

        await connection.commit();
        res.json({ success: true, message: `Appeal has been ${outcome.toLowerCase()}.` });

    } catch (error) {
        await connection.rollback();
        console.error('Error handling appeal:', error);
        res.status(500).json({ success: false, message: 'An error occurred.' });
    } finally {
        connection.release();
    }
});

// API to submit a new appeal
// API to submit a new appeal and send a Discord notification
app.post('/api/submit-appeal', isAuthenticated, async (req, res) => {
    const { punishment_id, punishment_type, reason } = req.body;
    const username = req.session.user.username;

    if (!reason) {
        return res.status(400).json({ success: false, message: 'Appeal reason is required.' });
    }
    try {
        // Insert the appeal and get its new ID
        const [result] = await dbPool.execute(
            'INSERT INTO `appeals` (username, punishment_id, punishment_type, reason, created_at) VALUES (?, ?, ?, ?, NOW())',
            [username, punishment_id, punishment_type, reason]
        );
        const newAppealId = result.insertId;

        // --- Send Discord Webhook Notification ---
        if (config.DISCORD_APPEAL_WEBHOOK_URL && config.WEBSITE_URL) {
            // Construct the direct link to the new appeal
            const appealLink = `${config.WEBSITE_URL}/staff/appeals/${newAppealId}`;

            const webhookPayload = {
                content: "@everyone", // This will mention everyone in the channel
                embeds: [{
                    title: "New Punishment Appeal Submitted",
                    description: `An appeal for a **${punishment_type}** has been submitted by **${username}**.`,
                    color: 16762880, // A nice orange/yellow color
                    fields: [
                        { name: "Player", value: `[${username}](${config.WEBSITE_URL}/profile/${username})`, inline: true },
                        // ✅ This field is now a direct link to the specific appeal
                        { name: "View Appeal", value: `[Click Here to View](${appealLink})`, inline: true }
                    ],
                    footer: {
                        text: `Appeal ID: ${newAppealId}` // Add the ID for easy reference
                    },
                    timestamp: new Date().toISOString()
                }]
            };

            try {
                await axios.post(config.DISCORD_APPEAL_WEBHOOK_URL, webhookPayload);
                console.log('[Discord] Appeal notification sent successfully.');
            } catch (webhookError) {
                console.error('[Discord] Failed to send appeal notification:', webhookError.message);
            }
        }

        res.json({ success: true, message: 'Your appeal has been submitted successfully.' });
    } catch (dbError) {
        console.error("Error submitting appeal:", dbError);
        res.status(500).json({ success: false, message: 'Failed to submit appeal.' });
    }
});
app.get('/api/active-mutes', isSeniorStaff, async (req, res) => {
    try {
        res.setHeader('Cache-Control', 'no-store');
        
        // Fetches mutes that are either permanent or have not expired yet
        const [rows] = await dbPool.execute(
            `SELECT muteid, ign, muteBy, muteReason, muteDuration, muteExpiresAt 
             FROM \`deep_punishments\` 
             WHERE (muteExpiresAt = 0 OR muteExpiresAt > UNIX_TIMESTAMP() * 1000) AND muteid IS NOT NULL
             ORDER BY muteid DESC`
        );
        res.json(rows);
    } catch (dbError) {
        console.error('Database query error (active-mutes):', dbError);
        res.status(500).json({ error: 'Failed to fetch active mutes.' });
    }
});
app.get('/api/active-bans', isSeniorStaff, async (req, res) => {
    try {
        res.setHeader('Cache-Control', 'no-store');
        
        // Fetches bans that are either permanent (banExpiresAt = 0) or have not expired yet
        const [rows] = await dbPool.execute(
            `SELECT banid, ign, banBy, banReason, banDuration, banExpiresAt 
             FROM \`deep_punishments\` 
             WHERE banExpiresAt = 0 OR banExpiresAt > UNIX_TIMESTAMP() * 1000 
             ORDER BY banid DESC`
        );
        res.json(rows);
    } catch (dbError) {
        console.error('Database query error (active-bans):', dbError);
        res.status(500).json({ error: 'Failed to fetch active bans.' });
    }
});
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        // Step 1: Authenticate against the 'auth_users' table
        const [authRows] = await dbPool.execute('SELECT * FROM `auth_users` WHERE `username` = ?', [username]);
        if (authRows.length === 0) {
            return res.json({ success: false, message: 'Invalid username or password.' });
        }
        const userAuth = authRows[0];
        const passwordMatch = await bcrypt.compare(password, userAuth.password);

        if (passwordMatch) {
            // Step 2: If auth is successful, get required data from other tables
            const [playerDataRows] = await dbPool.execute(
                `SELECT lp.uuid, lp.primary_group 
                 FROM luckperms_players AS lp 
                 WHERE lp.username = ?`,
                [username]
            );

            if (playerDataRows.length === 0) {
                return res.status(404).json({ success: false, message: 'Could not find player permission data.' });
            }
            const playerData = playerDataRows[0];

            // Set the user as online
            await dbPool.execute('UPDATE `auth_users` SET `is_logged_in` = 1 WHERE `username` = ?', [username]);

            // Step 3: Create the session with all correct data
            req.session.user = {
                username: userAuth.username,
                ign: username,
                uuid: playerData.uuid,
                primary_group: playerData.primary_group // <-- Get group from luckperms_players
            };
            
            req.session.save(err => {
                if (err) {
                    return res.status(500).json({ success: false, message: 'Server error during login.' });
                }
                res.json({ success: true, message: `Successfully logged in!` });
            });
        } else {
            res.json({ success: false, message: 'Invalid username or password.' });
        }
    } catch (dbError) {
        console.error('[Server] Database or bcrypt error:', dbError);
        res.status(500).json({ success: false, message: 'A server error occurred.' });
    }
});

app.post('/logout', isAuthenticated, (req, res) => {
    const username = req.session.user.username;
    dbPool.execute('UPDATE `auth_users` SET `is_logged_in` = 0 WHERE `username` = ?', [username])
        .then(() => {
            req.session.destroy(err => {
                if (err) {
                    return res.status(500).json({ success: false, message: 'Could not log out.' });
                }
                res.clearCookie('connect.sid');
                return res.json({ success: true, message: 'Logged out successfully.' });
            });
        })
        .catch(dbError => {
            res.status(500).json({ success: false, message: 'Error during logout.' });
        });
});

app.get('/api/auth/status', async (req, res) => {
    if (req.session.user) {
        try {
            // ✅ FIX: Re-fetch the user's current group from the database on every page load
            const [rows] = await dbPool.execute(
                'SELECT primary_group FROM `luckperms_players` WHERE `username` = ?',
                [req.session.user.username]
            );

            if (rows.length === 0) {
                // If the user was deleted from LuckPerms, destroy their session
                return req.session.destroy(() => {
                    res.json({ loggedIn: false });
                });
            }

            // Update the session with the latest group
            req.session.user.primary_group = rows[0].primary_group;

            // Send the updated user object to the browser
            res.json({ loggedIn: true, user: req.session.user });

        } catch (dbError) {
            console.error('[Server] Error re-fetching user group:', dbError);
            res.status(500).json({ error: 'Failed to verify user status.' });
        }
    } else {
        res.json({ loggedIn: false });
    }
});

app.get('/api/news', (req, res) => {
    const newsData = [
        { id: 1, title: "New Server Update v1.2!", content: "A massive update with new quests and a PVP arena.", author: "DeepMC Admin", date: "2025-07-28" },
        { id: 2, title: "Summer Event Coming Soon", content: "Get ready for exclusive items and new mini-games!", author: "DeepMC Admin", date: "2025-07-25" }
    ];
    res.json(newsData);
});

app.get('/api/top-playtime', async (req, res) => {
    try {
        res.setHeader('Cache-Control', 'no-store');
        const [rows] = await dbPool.execute(`
            SELECT db.ign AS username, db.playtime, lgp.permission AS suffix_permission
            FROM deepbungee AS db
            LEFT JOIN luckperms_players AS lp ON db.uuid = lp.uuid
            LEFT JOIN luckperms_group_permissions AS lgp ON lp.primary_group = lgp.name AND lgp.permission LIKE 'suffix.%'
            ORDER BY db.playtime DESC
            LIMIT 5
        `);
        const playersWithColors = rows.map(player => {
            const { style } = player.suffix_permission ? parseMinecraftColors(player.suffix_permission) : { style: '' };
            return { ...player, colorStyle: style };
        });
        res.json(playersWithColors);
    } catch (dbError) {
        res.status(500).json({ error: 'Failed to fetch top players.' });
    }
});
// Add these two new endpoints to your API section in server.js

// API to DELETE a word
app.delete('/api/word/:id', isSeniorStaff, async (req, res) => {
    try {
        const { id } = req.params;
        await dbPool.execute('DELETE FROM `words` WHERE id = ?', [id]);
        res.json({ success: true, message: 'Word deleted successfully.' });
    } catch (dbError) {
        console.error('Database query error (delete word):', dbError);
        res.status(500).json({ error: 'Failed to delete word.' });
    }
});
app.get('/guilds', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'html', 'guilds.html'));
})
// Add this to your API Endpoints section
// API endpoint to get the list of guilds with all details
app.get('/api/guilds', async (req, res) => {
    try {
        res.setHeader('Cache-Control', 'no-store');

        // This query now fetches the owner's username from auth_users for correct capitalization
        const sql = `
            SELECT 
                g.id, 
                g.name, 
                g.tag,
                g.tag_color,
                g.created_at,
                au.username AS owner_name,
                lgp.permission AS owner_suffix_permission,
                (SELECT COUNT(*) FROM guild_members WHERE guild_id = g.id) AS member_count
            FROM 
                guilds AS g
            LEFT JOIN 
                luckperms_players AS lp ON g.owner_uuid = lp.uuid
            LEFT JOIN
                auth_users AS au ON g.owner_uuid = au.uuid
            LEFT JOIN
                luckperms_group_permissions AS lgp ON lp.primary_group = lgp.name AND lgp.permission LIKE 'suffix.%'
            ORDER BY 
                member_count DESC
        `;

        const [rows] = await dbPool.execute(sql);

        // Process the results to parse color codes
        const guildsWithData = rows.map(guild => {
            const { style: ownerColorStyle } = guild.owner_suffix_permission 
                ? parseMinecraftColors(guild.owner_suffix_permission) 
                : { style: '' };

            const { style: tagColorStyle } = guild.tag_color 
                ? parseMinecraftColors(guild.tag_color) 
                : { style: '' };

            return { ...guild, ownerColorStyle, tagColorStyle };
        });

        res.json(guildsWithData);

    } catch (dbError) {
        console.error('Database query error (guilds):', dbError);
        res.status(500).json({ error: 'Failed to fetch guilds.' });
    }
});
app.get('/guild/:guildName', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'html', 'guild-profile.html'));
});
// Add this to your API Endpoints section
// API endpoint to get a single guild's profile data
app.get('/api/guild/:guildName', async (req, res) => {
    try {
        const { guildName } = req.params;
        res.setHeader('Cache-Control', 'no-store');

        // --- Get Guild's Basic Info ---
        const [guildRows] = await dbPool.execute(
            `SELECT g.id, g.name, g.tag, g.created_at, 
            (SELECT COUNT(*) FROM guild_members WHERE guild_id = g.id) AS member_count
            FROM guilds AS g WHERE g.name = ?`,
            [guildName]
        );

        if (guildRows.length === 0) {
            return res.status(404).json({ error: 'Guild not found.' });
        }
        const guildInfo = guildRows[0];

        // --- Get Guild's Member List with Rank Priority ---
        // ✅ This query now fetches and sorts by 'priority'
        const [memberRows] = await dbPool.execute(
            `SELECT 
                gm.player_uuid AS uuid, gm.joined_at,
                au.username,
                lgp.permission AS suffix_permission,
                au.last_login,
                gr.name AS guild_rank_name,
                gr.priority 
            FROM guild_members AS gm
            LEFT JOIN guild_ranks AS gr ON gm.rank_id = gr.id
            LEFT JOIN luckperms_players AS lp ON gm.player_uuid = lp.uuid
            LEFT JOIN auth_users AS au ON gm.player_uuid = au.uuid
            LEFT JOIN luckperms_group_permissions AS lgp ON lp.primary_group = lgp.name AND lgp.permission LIKE 'suffix.%'
            WHERE gm.guild_id = ?
            ORDER BY gr.priority DESC`, // Sort by priority descending
            [guildInfo.id]
        );

        // Process members to add color style
        const membersWithData = memberRows.map(member => {
            const { style } = member.suffix_permission ? parseMinecraftColors(member.suffix_permission) : { style: '' };
            return { ...member, colorStyle: style };
        });

        res.json({ guildInfo, members: membersWithData });

    } catch (dbError) {
        console.error('Database query error (guild profile):', dbError);
        res.status(500).json({ error: 'Failed to fetch guild data.' });
    }
});
// API to UPDATE a word
app.put('/api/word/:id', isSeniorStaff, async (req, res) => {
    try {
        const { id } = req.params;
        const { reason, note } = req.body;
        const updated_by = req.session.user.username;

        const finalReason = note ? `${reason} | ${note}` : reason;
        const is_banned = reason !== "Allowed";

        await dbPool.execute(
            'UPDATE `words` SET reason = ?, is_banned = ?, added_by = ?, last_edited = NOW() WHERE id = ?',
            [finalReason, is_banned, updated_by, id]
        );
        res.json({ success: true, message: 'Word updated successfully.' });
    } catch (dbError) {
        console.error('Database query error (update word):', dbError);
        res.status(500).json({ error: 'Failed to update word.' });
    }
});
app.get('/api/staff', async (req, res) => {
    try {
        res.setHeader('Cache-Control', 'no-store');

        const rankOrder = ['owner', 'manager', 'headadmin', 'admin', 'srmod', 'seniormod', 'mod'];
        const fieldPlaceholders = rankOrder.map(() => '?').join(',');

        const sqlQuery = `
            SELECT
                au.username,
                lp.primary_group,
                lp.uuid,
                db.playtime,
                au.is_logged_in,
                lgp.permission AS suffix_permission
            FROM
                luckperms_players AS lp
            LEFT JOIN
                deepbungee AS db ON lp.uuid = db.uuid
            LEFT JOIN
                auth_users AS au ON lp.uuid = au.uuid
            LEFT JOIN
                luckperms_group_permissions AS lgp ON lp.primary_group = lgp.name AND lgp.permission LIKE 'suffix.%'
            WHERE
                lp.primary_group IN (${fieldPlaceholders})
            ORDER BY
                FIELD(lp.primary_group, ${fieldPlaceholders})
        `;

        // Pass the same rankOrder twice (for IN and FIELD)
        const sqlParams = [...rankOrder, ...rankOrder];

        const [rows] = await dbPool.execute(sqlQuery, sqlParams);

        const playersWithColors = rows.map(player => {
            const { style, hexColor } = player.suffix_permission 
                ? parseMinecraftColors(player.suffix_permission) 
                : { style: '', hexColor: '#00AAAA' };
            return { ...player, colorStyle: style, rankColor: hexColor || '#00AAAA' };
        });

        res.json(playersWithColors);
    } catch (dbError) {
        console.error('Database query error (staff):', dbError);
        res.status(500).json({ error: 'Failed to fetch staff list.' });
    }
});

// Add this to your API Endpoints section
app.post('/api/reports/close/:id', isSeniorStaff, async (req, res) => {
    const reportId = req.params.id;
    const handled_by = req.session.user.username;
    const { outcome } = req.body;
    const connection = await dbPool.getConnection();

    if (!outcome) {
        return res.status(400).json({ success: false, message: 'Outcome is required.' });
    }

    try {
        await connection.beginTransaction();

        // Step 1: Get the original report data
        const [reportRows] = await connection.execute('SELECT * FROM `reports` WHERE id = ?', [reportId]);
        if (reportRows.length === 0) {
            throw new Error('Report not found.');
        }
        const report = reportRows[0];

        // Step 2: Insert the data into the history table
        await connection.execute(
            `INSERT INTO reports_history (report_id, reporter_username, reported_username, report_type, evidence_link, extra_notes, handled_by, outcome, report_created_at) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [report.id, report.reporter_username, report.reported_username, report.report_type, report.evidence_link, report.extra_notes, handled_by, outcome, report.created_at]
        );

        // Step 3: Delete the original report from the active table
        await connection.execute('DELETE FROM `reports` WHERE id = ?', [reportId]);

        // Step 4: Commit the transaction
        await connection.commit();
        res.json({ success: true, message: 'Report has been closed and moved to history.' });

    } catch (error) {
        await connection.rollback();
        console.error('Error closing report:', error);
        res.status(500).json({ success: false, message: 'An error occurred.' });
    } finally {
        connection.release();
    }
});
// API endpoint to get a single player's profile data
app.get('/api/player/:username', async (req, res) => {
    try {
        const username = req.params.username;
        res.setHeader('Cache-Control', 'no-store');

        // This query now also joins with guild tables to get the player's guild tag
        const sql = `
            SELECT
                au.username, 
                lp.primary_group, 
                lp.uuid,
                db.playtime,
                au.is_logged_in,
                lgp.permission AS suffix_permission,
                pvp.points, pvp.kills, pvp.deaths, pvp.shards,
                g.name AS guild_name,
                g.tag AS guild_tag,
                g.tag_color AS guild_tag_color
            FROM auth_users AS au
            LEFT JOIN luckperms_players AS lp ON au.uuid = lp.uuid
            LEFT JOIN deepbungee AS db ON au.uuid = db.uuid
            LEFT JOIN luckperms_group_permissions AS lgp ON lp.primary_group = lgp.name AND lgp.permission LIKE 'suffix.%'
            LEFT JOIN pvp_nullping AS pvp ON au.uuid = pvp.uuid
            LEFT JOIN guild_members AS gm ON au.uuid = gm.player_uuid
            LEFT JOIN guilds AS g ON gm.guild_id = g.id
            WHERE au.username = ?
        `;

        const [rows] = await dbPool.execute(sql, [username]);

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Player not found' });
        }

        const player = rows[0];
        const { style: colorStyle, hexColor } = player.suffix_permission 
            ? parseMinecraftColors(player.suffix_permission) 
            : { style: '', hexColor: '#00AAAA' };
        
        const { style: guildTagStyle } = player.guild_tag_color
            ? parseMinecraftColors(player.guild_tag_color)
            : { style: '' };

        res.json({ ...player, colorStyle, rankColor: hexColor || '#00AAAA', guildTagStyle });

    } catch (dbError) {
        console.error('Database query error (player profile):', dbError);
        res.status(500).json({ error: 'Failed to fetch player profile.' });
    }
});

// --- Server Start ---
app.listen(PORT, () => {
    console.log(`DeepMC server running at http://localhost:${PORT}`);
});