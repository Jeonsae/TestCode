const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mysql = require('mysql');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = 3000;

// MySQL 데이터베이스 연결 설정
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '1234',
    database: 'example',
});

// 비밀번호 해시화
const hashPassword = async (password) => {
    const saltRounds = 10; // salt의 강도
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    return hashedPassword;
};

// 비밀번호 확인
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

    // 중복된 인증 코드 삭제
    const deleteExistingCodeQuery = 'DELETE FROM verification_codes WHERE email = ?';
    db.query(deleteExistingCodeQuery, [email], (err) => {
        if (err) return res.status(500).json({ error: '기존 인증 코드 삭제 실패' });

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
    const {
        userName,       // 사용자 이름
        userEmail,      // 이메일
        userNum,        // 학번
        userPhone,      // 전화번호
        college,        // 단과대학
        userLesson,     // 전공
        Field,          // 성별
        userImg,        // 프로필 이미지 URL
        userPW          // 비밀번호
    } = req.body;

    try {
        // 비밀번호 해싱
        const hashedPassword = await hashPassword(userPW);

        // 데이터베이스에 데이터 삽입
        const query = `
            INSERT INTO users (userName, userEmail, userNum, userPhone, college, userLesson, Field, userImg, userPW)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;
        const values = [
            userName,
            userEmail,
            userNum,
            userPhone,
            college,
            userLesson,
            Field,
            userImg,
            hashedPassword
        ];

        console.log('삽입할 데이터:', values); // 디버깅용

        db.query(query, values, (err, result) => {
            if (err) {
                console.error('데이터 삽입 실패: ', err);
                return res.status(500).json({ error: '회원가입 실패' });
            }
            res.status(201).json({ message: '회원가입 성공' });
        });
    } catch (error) {
        console.error('서버 오류: ', error);
        res.status(500).json({ error: '서버 오류' });
    }
});




// 로그인 API
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    db.query('SELECT * FROM users WHERE userEmail = ?', [email], async (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Server error' });
        }
        if (results.length === 0) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const user = results[0];

        // 해시된 비밀번호와 비교
        const match = await comparePassword(password, user.userPW);

        if (!match) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // JWT 생성
        const token = jwt.sign({ id: user.userEmail }, 'yourSecretKey', { expiresIn: '1h' });

        console.log("JWT Token:", token);

        res.json({ token });
    });
});

//비밀번호 찾기 과정
app.post('/update-password', (req, res) => {
    const { email, newPassword } = req.body;
  
    if (!email || !newPassword) {
      return res.status(400).send({ message: '이메일과 새 비밀번호를 모두 제공해야 합니다.' });
    }
  
    bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
      if (err) {
        return res.status(500).send({ message: '비밀번호 암호화 실패' });
      }
  
      const query = 'UPDATE users SET userPW = ? WHERE userEmail = ?';
      db.query(query, [hashedPassword, email], (err, result) => {
        if (err) {
          return res.status(500).send({ message: '비밀번호 변경 실패' });
        }
  
        if (result.affectedRows === 0) {
          return res.status(404).send({ message: '이메일을 찾을 수 없습니다.' });
        }
  
        return res.status(200).send({ message: '비밀번호가 성공적으로 변경되었습니다.' });
      });
    });
  });

// Socket.io 연결 설정
io.on('connection', (socket) => {
    console.log('User connected:', socket.id);

    // 클라이언트가 메시지를 보내면 모든 클라이언트에 브로드캐스트
    socket.on('message', (message) => {
        // JWT 토큰 검증
        const token = message.token;

        try {
            const decoded = jwt.verify(token, 'yourSecretKey'); // JWT 검증
            message.user = decoded.id; // 메시지에 사용자 ID 추가

            const messageWithId = {
                ...message,
                _id: Date.now() + Math.random(), // 고유한 ID 생성
            };

            // 메시지를 보낸 클라이언트는 제외하고 다른 클라이언트에게만 메시지 전송
            socket.broadcast.emit('message', messageWithId); // 자신을 제외한 모든 클라이언트에게 메시지 전송
        } catch (error) {
            console.error('Token validation failed:', error);
            socket.emit('message', { text: 'Unauthorized', _id: Date.now() });
        }
    });

    // 클라이언트 연결이 끊겼을 때
    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.id);
    });
});


// 서버 시작
server.listen(PORT, () => {
    console.log(`서버가 ${PORT}번 포트에서 실행 중입니다.`);
});
