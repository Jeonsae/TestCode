const express = require('express');
const mysql = require('mysql');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();
const PORT = 3000;

// MySQL 데이터베이스 연결 설정
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '1234',
    database: 'example',
});

//비밀번호해시화
const hashPassword = async (password) => {
    const saltRounds = 10; // salt의 강도
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    return hashedPassword;
};


//비밀번호 확인
const comparePassword = async (plainPassword, hashedPassword) => {
    const match = await bcrypt.compare(plainPassword, hashedPassword);
    return match;
};

// MySQL 서버에 연결
db.connect((err) => {
    if (err) {
        console.error('MySQL 연결 실패: ', err);
        return;
    }
    console.log('MySQL에 성공적으로 연결되었습니다.');
});

app.use(express.json());
app.use(cors());

// nodemailer 설정
let transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: 'clubgnu1@gmail.com', // 전송하는 이메일(공용 이메일)
        pass: 'gnfu gmuu ufid mgow' // 비밀번호
    }
});

// 인증 코드 생성 및 이메일 전송
app.post('/send-verification-code', (req, res) => {
    const { email } = req.body;

    const code = Math.floor(100000 + Math.random() * 900000).toString(); // 6자리 랜덤 코드
    const expiresAt = new Date(Date.now() + 5 * 60000); // 5분 유효

    // 인증 코드 DB에 저장
    const insertQuery = 'INSERT INTO verification_codes (email, code, expires_at) VALUES (?, ?, ?)';
    db.query(insertQuery, [email, code, expiresAt], (err) => {
        if (err) return res.status(500).json({ error: '인증 코드 생성 실패' });

        // 이메일 전송 설정
        let mailOptions = {
            from: 'clubgnu1@gmail.com',
            to: email,
            subject: '인증 코드 요청',
            text: `귀하의 인증 코드는 ${code}입니다. 5분 이내에 입력해 주세요.`
        };

        // 이메일 전송
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('이메일 전송 실패:', error);
                return res.status(500).json({ error: '이메일 전송 실패' });
            }
            console.log('인증 코드가 이메일로 발송되었습니다:', info.response);
            res.status(200).json({ message: '인증 코드가 발송되었습니다.' });
        });
    });
});

// 인증 코드 검증
app.post('/verify-code', (req, res) => {
    const { email, code } = req.body;

    const checkQuery = 'SELECT * FROM verification_codes WHERE email = ? AND code = ? AND expires_at > NOW()';
    db.query(checkQuery, [email, code], (err, results) => {
        if (err) return res.status(500).json({ error: '인증 코드 확인 실패' });
        if (results.length === 0) return res.status(400).json({ error: '유효하지 않은 인증 코드' });

        res.status(200).json({ message: '인증 성공' });
    });
});

// 회원가입 API
app.post('/signup', async (req, res) => {
    const { student_id, email, password, nickname } = req.body;

    try {
        const hashedPassword = await hashPassword(password);

        const query = 'INSERT INTO users (student_id, email, password, nickname) VALUES (?, ?, ?, ?)';
        const values = [student_id, email, hashedPassword, nickname];

        db.query(query, values, (err, result) => {
            if (err) {
                console.error('데이터 삽입 실패: ', err);
                return res.status(500).json({ error: '회원가입 실패' });
            }
            res.status(201).json({ message: '회원가입 성공' });
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: '비밀번호 해싱 실패' });
    }
});

// 로그인 API
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Server error' });
        }
        if (results.length === 0) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const user = results[0];

        // 해시된 비밀번호와 비교
        const match = await comparePassword(password, user.password);

        if (!match) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // JWT 생성
        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET_KEY, { expiresIn: '1h' });

        console.log("JWT Token:", token);

        res.json({ token });
    });
});

// 서버 실행
app.listen(PORT, () => {
    console.log(`서버가 ${PORT}번 포트에서 실행 중입니다.`);
});
