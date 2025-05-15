const express = require('express');
const axios = require("axios");

const https = require('https');

const fs = require('fs');
const os = require("os");
const path = require('path');

const multer = require("multer");


const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
var port = 3000;

// // Replace with your actual certificate paths
const options = {
    key: fs.readFileSync(path.join(__dirname, 'server.key')),
    cert: fs.readFileSync(path.join(__dirname, 'server.cert')),
};

const dbFilePath = path.join(__dirname, 'db.json');

const usersFilePath = path.join(__dirname, 'users.json');

const uploadDir = path.join(__dirname, "fileStorage");

const storagePath = "/"; // Root directory (change if needed)

// 🔹 Define storage limit per user (e.g., 1GB = 1 * 1024 * 1024 * 1024 bytes)
const USER_STORAGE_LIMIT = 1 * 1024 * 1024 * 1024;

if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const userFolder = path.join(uploadDir, req.user.id);
        if (!fs.existsSync(userFolder)) {
            fs.mkdirSync(userFolder);
        }
        cb(null, userFolder);
    },
    filename: (req, file, cb) => {
        // const filename = path.join(file.filename + path.basename(file.originalname));
        cb(null, file.originalname);
        // cb(null, Date.now() + path.extname(file.originalname)) 

    }
});

// 📌 Function to get the size of a file
function getFileSize(filePath) {
    try {
        const stats = fs.statSync(filePath);
        return stats.size; // Returns file size in bytes
    } catch (error) {
        console.error("Error getting file size:", error);
        return 0;
    }
}

// 🔹 Function to get total storage used by a user
const getUserStorageUsage = (userId) => {
    const userFolder = path.join(uploadDir, userId);
    if (!fs.existsSync(userFolder)) return 0;

    return fs.readdirSync(userFolder).reduce((total, file) => {
        const filePath = path.join(userFolder, file);
        const stats = fs.statSync(filePath);
        return total + stats.size;
    }, 0);
};


// const upload = multer({ storage });
const upload = multer({
    storage,
    limits: { fileSize: 50 * 1024 * 1024 }, // Limit each file to 50MB
    fileFilter: (req, file, cb) => {
        const userStorageUsed = getUserStorageUsage(req.user.id);
        const fileSize = req.headers["content-length"];

        if (userStorageUsed + Number(fileSize) > USER_STORAGE_LIMIT) {
            return cb(new Error("Storage limit exceeded"), false);
        }
        cb(null, true);
    }
});

app.use(express.json());
app.use(cors());

app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*'); // Allow requests from any origin
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE', 'PATCH'); // Allowed methods
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization'); // Allowed headers
    next();
});

const SECRET_KEY = 'your_secret_key'; // Use a secure key in production

// Mock database
let users = [];

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ message: 'Forbidden' });
        req.user = user;
        next();
    });
};

// 🔹 API: Get User Storage Usage
app.get("/user/storage", authenticateToken, (req, res) => {
    const usedStorage = getUserStorageUsage(req.user.id);
    res.json({
        used: usedStorage,
        limit: USER_STORAGE_LIMIT,
        available: USER_STORAGE_LIMIT - usedStorage
    });
});

// 📌 API Route to Get File Size
app.get("/filesize/:filename", authenticateToken, (req, res) => {
    const filePath = path.join(uploadDir, req.user.id, req.params.filename); // Change "uploads" to your actual directory
    const fileSize = getFileSize(filePath);
    res.json({ file: req.params.filename, size: fileSize });
});

// Upload file
app.post("/upload", authenticateToken, upload.single("file"), (req, res) => {
    res.json({ message: "File uploaded", filename: req.file.filename, folder: req.user.id });
});

// Get list of files
app.get("/files", authenticateToken, (req, res) => {
    const userFolder = path.join(uploadDir, req.user.id);
    if (!fs.existsSync(userFolder)) {
        return res.json([]);
    }
    fs.readdir(userFolder, (err, files) => {
        if (err) return res.status(500).json({ error: "Error reading files" });
        res.json(files);
    });
});

// Download file
app.get("/files/:filename", authenticateToken, (req, res) => {
    const filePath = path.join(uploadDir, req.user.id, req.params.filename);
    if (fs.existsSync(filePath)) {
        res.download(filePath);
    } else {
        res.status(404).json({ error: "File not found" });
    }
});

// Delete file
app.delete("/files/:filename", authenticateToken, (req, res) => {
    const filePath = path.join(uploadDir, req.user.id, req.params.filename);
    if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        res.json({ message: "File deleted" });
    } else {
        res.status(404).json({ error: "File not found" });
    }
});

// Read users from the "database" (users.json file)
const readUsersFromFile = () => {
    try {
        const data = fs.readFileSync(usersFilePath, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('Error reading users from file:', error);
        return [];
    }
};

// Write users to the "database" (users.json file)
const writeUsersToFile = (users) => {
    try {
        fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2), 'utf8');
    } catch (error) {
        console.error('Error writing users to file:', error);
    }
};

// 👉 Signup Route
app.post('/auth/signup', async (req, res) => {
    const { email, password } = req.body;
    const users = readUsersFromFile();

    const existingUser = users.find((u) => u.email === email);
    if (existingUser) return res.status(400).json({ message: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { id: Date.now().toString(), email, name: '', displayName: '', password: hashedPassword, admin: false };

    users.push(newUser); // Add the new user to the "database"
    writeUsersToFile(users); // Save the updated list of users
    fs.mkdirSync('./users/' + newUser.id);
    var data = { collections: {} }; // JSON content
    // console.log(JSON.stringify(data));
    writeFile('./users/' + newUser.id + '/db.json', data);

    const token = jwt.sign({ id: newUser.id, email: newUser.email }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token, user: { email: newUser.email } });
});

// 👉 Login Route
app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;
    // console.log(email + ' ' + password);
    const users = readUsersFromFile();

    const user = users.find((u) => u.email === email);
    if (!user) return res.status(400).json({ message: 'User not found' });

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) return res.status(401).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: '24h' });
    res.json({ token, user: { email: user.email, displayName: user.displayName, admin: user.admin } });
});

// 👉 Logout Route (Client-Side)
app.post('/auth/logout', (req, res) => {
    res.json({ message: 'Logged out' });
});

// 👉 Get Current User Route
app.get('/auth/me', authenticateToken, async (req, res) => {
    const users = readUsersFromFile();
    users.find((u) => {
        // if (u.id === req.user.id) console.log('found user ' + u.email)
        // console.log(u.email);
    })
    const user = await users.find((u) => u.id === req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    res.json({ user: { email: user.email, displayName: user.displayName } });
});

// 👉 Protected Route Example
app.get('/api/protected', authenticateToken, (req, res) => {
    res.json({ message: `Hello, ${req.user.email}` });
});

// Helper functions to read and write data
function readData() {
    const data = fs.readFileSync(dbFilePath);
    return JSON.parse(data);
}

function writeData(data) {
    fs.writeFileSync(dbFilePath, JSON.stringify(data, null, 2));
}

// 👉 Helper function to read from JSON file
function readFile(path) {
    const data = fs.readFileSync(path, 'utf-8');
    return JSON.parse(data);
};

// 👉 Helper function to write to JSON file
function writeFile(path, data) {
    fs.writeFileSync(path, JSON.stringify(data, null, 2), 'utf-8');
};

// ---------------------- COLLECTIONS ----------------------

// Get all collections
app.get('/collections', authenticateToken, (req, res) => {
    // console.log('token = ' + req.user.id);
    const data = readFile('./users/' + req.user.id + '/db.json');
    res.json(Object.keys(data.collections));
});


// Update a document
app.put("/collections/:name/:docId", authenticateToken, (req, res) => {
    const db = readFile('./users/' + req.user.id + '/db.json');
    //loadDB();
    if (!db[req.params.name]) db[req.params.name] = {};
    db[req.params.name][req.params.docId] = req.body;
    // saveDB(db);
    writeFile('./users/' + req.user.id + '/db.json', db);
    res.json({ success: true });
});

app.post('/collections/:name', authenticateToken, (req, res) => {
    const data = readFile('./users/' + req.user.id + '/db.json');
    //readData();
    const name = req.params.name;
    const id = req.user.id;

    // console.log(id + ' ' + name);

    if (data.collections[name]) {
        return res.status(400).send('Collection already exists');
    }

    data.collections[name] = { documents: {} };
    // writeData(data);
    writeFile('./users/' + req.user.id + '/db.json', data);
    res.status(201).json({ message: `Collection '${name}' created` });
});

// Delete a collection
app.delete('/collections/:name', authenticateToken, (req, res) => {
    const data = readFile('./users/' + req.user.id + '/db.json');
    //readData();
    const name = req.params.name;

    if (!data.collections[name]) {
        return res.status(404).send('Collection not found');
    }

    delete data.collections[name];
    // writeData(data);
    writeFile('./users/' + req.user.id + '/db.json', data);
    res.json({ message: `Collection '${name}' deleted` });
});

// ---------------------- ITEMS IN COLLECTIONS ----------------------

// Get all items in a collection
app.get('/collections/:name/documents/', authenticateToken, (req, res) => {
    const data = readFile('./users/' + req.user.id + '/db.json');
    //readData();
    // console.log(data);
    const { name } = req.params;
    // console.log(name);
    res.json(data.collections[name]?.documents || {});
});

// Create a new document in a collection
app.post('/collections/:name/documents/:docId', authenticateToken, (req, res) => {
    // const data = readData();
    const data = readFile('./users/' + req.user.id + '/db.json');
    const { name, docId } = req.params;
    console.log(req.params);
    console.log(req.body);
    const newDocument = req.body;

    if (!data.collections[name]) {
        return res.status(404).json({ message: `Collection ${name} not found` });
    }

    data.collections[name].documents[docId] = {};
    data.collections[name].documents[docId] = newDocument;
    // writeData(data);
    writeFile('./users/' + req.user.id + '/db.json', data);
    res.json({ message: `Document ${docId} created in collection ${name}` });
});


// Get a single document from a collection
app.get('/collections/:name/documents/:docId', authenticateToken, (req, res) => {
    // const data = readData();
    const data = readFile('./users/' + req.user.id + '/db.json');
    const { name, docId } = req.params;
    const document = data.collections[name]?.documents[docId];

    if (!document) {
        return res.status(404).json({ message: `Document ${docId} not found in collection ${name}` });
    }

    res.json(document);
});

// Update a document in a collection
app.put('/collections/:name/documents/:docId', authenticateToken, (req, res) => {
    // const data = readData();
    const data = readFile('./users/' + req.user.id + '/db.json');
    const { name, docId } = req.params;
    console.log(req.params)


    if (!data.collections[name]?.documents[docId]) {
        return res.status(404).json({ message: `Document ${docId} not found in collection ${name}` });
    }

    data.collections[name].documents[docId] = req.body;
    // writeData(data);
    writeFile('./users/' + req.user.id + '/db.json', data);
    res.json({ message: `Document ${docId} updated in collection ${name}` });
});

// Delete a document from a collection
app.delete('/collections/:name/documents/:docId', authenticateToken, (req, res) => {
    // const data = readData();
    const data = readFile('./users/' + req.user.id + '/db.json');
    const { name, docId } = req.params;

    if (!data.collections[name]?.documents[docId]) {
        return res.status(404).json({ message: `Document ${docId} not found` });
    }

    delete data.collections[name].documents[docId];
    // writeData(data);
    writeFile('./users/' + req.user.id + '/db.json', data);
    res.json({ message: `Document ${docId} deleted from collection ${name}` });
});

function searchInObject(obj, term, basePath = '') {
    let results = [];

    for (const key in obj) {
        const value = obj[key];
        const path = basePath ? `${basePath}.${key}` : key;

        // Check key match
        if (key.includes(term)) {
            results.push({ path, key, value });
        }

        // Check value match
        if (typeof value === 'string' && value.includes(term)) {
            results.push({ path, key, value });
        }

        // Recursively search in nested objects
        if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
            results = results.concat(searchInObject(value, term, path));
        }
    }

    return results;
}


app.get('/search', authenticateToken, async (req, res) => {
    const term = req.query.term;
    if (!term) return res.status(400).json({ error: 'Missing search term' });
    if (term.length < 4) return res.status(400).json({ error: 'Search term to short' });

    const userId = req.user.id;
    const db = await readFile('./users/' + req.user.id + '/db.json');

    const results = {};

    for (const [docId, docData] of Object.entries(db.collections)) {
        const matches = searchInObject(docData, term);
        if (matches.length > 0) {
            results[docId] = matches
            // results.push({ documentId: docId, matches });
        }
    }

    res.json(results);
});


app.get("/search-old", authenticateToken, async (req, res) => {
    const { term } = req.query;
    const userId = req.user.id;
    const db = await readFile('./users/' + req.user.id + '/db.json');
    //loadUserDatabase(userId);

    const results = [];

    const searchDocs = (collectionName, docs, results, pathPrefix = "") => {
        var index = -1;
        for (let doc in docs) {
            index++;

            // docs.forEach((doc, index) => {
            console.log(index);
            const matchedFields = [];

            const scan = (obj, path = []) => {
                for (let key in obj) {
                    const value = obj[key];
                    const fullPath = [...path, key];
                    const fullKeyPath = fullPath.join(".");

                    if (
                        // fuzzymatch(key, term) ||
                        (typeof value === "string")
                        // && fuzzymatch(value, term)
                    ) {
                        matchedFields.push({ path: fullKeyPath, value });
                    }

                    if (typeof value === "object" && value !== null) {
                        if (Array.isArray(value)) {
                            value.forEach((item, i) => {
                                if (typeof item === "object") scan(item, [...fullPath, i]);
                            });
                        } else {
                            scan(value, fullPath);
                        }
                    }
                }
            };

            scan(doc);

            if (matchedFields.length) {
                results.push({
                    collection: `${pathPrefix}${collectionName}`,
                    index,
                    matches: matchedFields
                });
            }

            // Handle nested collections inside this document
            for (let key in doc) {
                console.log(doc[key])
                if (doc[key] && Array.isArray(doc[key])) { //&& typeof doc[key] === 'object'
                    searchDocs(key, doc[key].documents, results, `${pathPrefix}${collectionName}/`);
                    console.log(`${pathPrefix}${collectionName}/`)
                    // searchDocs(key, doc[key], results, `${pathPrefix}${collectionName}/`);
                }
            }

        }
        // );
    };

    for (let [collectionName, docs] of Object.entries(db.collections)) {
        // console.log(collectionName);
        searchDocs(collectionName, docs, results);
    }

    res.json(results);
});


// Function to get the external (public) IP
async function getPublicIP() {
    try {
        const response = await axios.get("https://api.ipify.org?format=json");
        return response.data.ip;
    } catch (error) {
        console.error("Failed to fetch public IP:", error);
        return "0.0.0.0"; // Fallback to listening on all interfaces
    }
}

const fuzzymatch = (target, term) => {
    const t = String(term).toLowerCase();
    const s = String(target).toLowerCase();
    return s.includes(t) || t.split("").every(char => s.includes(char));
};

// ---------------------- START SERVER ----------------------

// app.listen(port, () => {
//     console.log(`Server running at http://10.0.0.202:${port}`);
// });
// app.listen(port, "localhost", () => {
//     console.log(`Server running at http://localhost:${port}`);
// });

// Start the server after fetching the IP
// getPublicIP().then((ip) => {
port = 80
ip = "0.0.0.0"
// var ip = "localhost";
app.listen(port, ip, () => {
    console.log(`Server running at http://${ip}:${port}`);
});
// });

// Bind to 0.0.0.0 to listen on all interfaces
// https.createServer(options, app).listen(443, ip, () => {
//     console.log('HTTPS Server is running on https://0.0.0.0:443');
// });
