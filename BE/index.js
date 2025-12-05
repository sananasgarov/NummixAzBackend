import express from "express";
import nodemailer from "nodemailer";
import cors from "cors";
import dotenv from "dotenv";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();

app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

mongoose
  .connect("mongodb+srv://LeylaRustamova:LeylaRustamova@cluster0.jhalvrd.mongodb.net/")
  .then(() => console.log(" MongoDB connected"))
  .catch(() => console.log(" MongoDB connection failed"));

const JWT_SECRET = process.env.JWT_SECRET || "your_secret_key_here_change_in_production";

// ======================= ADMIN USER SCHEMA =======================
const adminSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const Admin = mongoose.model("Admin", adminSchema);

// ======================= AUTH MIDDLEWARE =======================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: "Token tapılmadı" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: "Token etibarsızdır" });
    }
    req.user = user;
    next();
  });
};

// ======================= REGISTER (DEACTIVATED) =======================
app.post("/api/auth/register", (req, res) => {
  return res.status(403).json({
    success: false,
    message: "Yeni admin qeydiyyatı bağlıdır. Əlavə admin yaradıla bilməz."
  });
});

// ======================= LOGIN =======================
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: "Email və şifrə daxil edin" });
    }

    
    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(401).json({ success: false, message: "Email və ya şifrə yanlışdır" });
    }

    const isPasswordValid = await bcrypt.compare(password, admin.password);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: "Email və ya şifrə yanlışdır" });
    }

    const token = jwt.sign(
      { id: admin._id, email: admin.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(200).json({
      success: true,
      message: "Daxil olma uğurlu",
      token,
      user: {
        id: admin._id,
        name: admin.name,
        email: admin.email
      }
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ success: false, message: "Daxil olma zamanı xəta baş verdi" });
  }
});

// ======================= CHECK EMAIL =======================
app.post("/api/auth/check-email", async (req, res) => {
  try {
    const { email } = req.body;
    const existingAdmin = await Admin.findOne({ email });
    res.json({ exists: !!existingAdmin });
  } catch (error) {
    res.status(500).json({ success: false, message: "Xəta baş verdi" });
  }
});

// ======================= VERIFY TOKEN =======================
app.get("/api/auth/verify", authenticateToken, async (req, res) => {
  try {
    const admin = await Admin.findById(req.user.id).select('-password');
    if (!admin) {
      return res.status(404).json({ success: false, message: "İstifadəçi tapılmadı" });
    }
    res.json({ success: true, user: admin });
  } catch (error) {
    res.status(500).json({ success: false, message: "Xəta baş verdi" });
  }
});

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// ======================= CONTACT =======================
app.post("/api/contact", async (req, res) => {
  try {
    const { fullName, email, companyName, message } = req.body;

    if (!fullName || !email || !message) {
      return res.status(400).json({ success: false, message: "Bütün sahələri doldurun" });
    }

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: "nummixaz@gmail.com",
      subject: `Yeni müraciət: ${fullName}`,
      html: `
        <div>
          <p><strong>Ad Soyad:</strong> ${fullName}</p>
          <p><strong>Email:</strong> ${email}</p>
          ${companyName ? `<p><strong>Şirkət:</strong> ${companyName}</p>` : ""}
          <p><strong>Mesaj:</strong> ${message}</p>
        </div>
      `,
    };

    const autoReplyOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Müraciətiniz qəbul edildi - Nummix",
      html: `<p>Hörmətli ${fullName}, müraciətiniz üçün təşəkkür edirik!</p>`,
    };

    await transporter.sendMail(mailOptions);
    await transporter.sendMail(autoReplyOptions);

    res.status(200).json({ success: true, message: "Mesajınız göndərildi" });
  } catch (error) {
    console.error("Email error:", error);
    res.status(500).json({ success: false, message: "Email göndərilmədi", error: error.message });
  }
});

// ======================= TEAM =======================
const teamSchema = new mongoose.Schema({
  image: String,
  name: String,
  position: String,
  description: String,
  linkedin: String,
  email: String,
});
const Team = mongoose.model("Team", teamSchema);


app.get("/team", async (req, res) => {
  try {
    res.json(await Team.find());
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post("/team", authenticateToken, async (req, res) => {
  try {
    const team = await Team.create(req.body);
    res.status(201).json(team);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.put("/team/:id", authenticateToken, async (req, res) => {
  try {
    const team = await Team.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true });
    if (!team) return res.status(404).json({ message: "Tapılmadı" });
    res.json(team);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.delete("/team/:id", authenticateToken, async (req, res) => {
  try {
    const team = await Team.findByIdAndDelete(req.params.id);
    if (!team) return res.status(404).json({ message: "Tapılmadı" });
    res.json({ message: "Silindi" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ======================= BLOG =======================
const blogSchema = new mongoose.Schema({
   title: String,
  category: String,
  excerpt: String,
  coverImage: String,
  date: String,
  readTime: String,
  author: {
    name: String,
    initials: String
  },

  question1: String,
  answer1: String,
  question2: String,
  answer2: String,
  question3: String,
  answer3: String,
  question4: String,
  answer4: String,
  question5: String,
  answer5: String,
  question6: String,
  answer6: String,
  question7: String,
  answer7: String,
  question8: String,
  answer8: String,
  question9: String,
  answer9: String,


  result: String
}, { timestamps: true });


const Blog = mongoose.model("Blog", blogSchema);

app.get("/blogs", async (req, res) => {
  try {
    res.json(await Blog.find().sort({ date: -1 }));
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/blogs/:id", async (req, res) => {
  try {
    const blog = await Blog.findById(req.params.id);
    if (!blog) {
      return res.status(404).json({ message: "Blog tapılmadı" });
    }
    res.json(blog);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post("/blogs", authenticateToken, async (req, res) => {
  try {
    const blog = await Blog.create(req.body);
    res.status(201).json(blog);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.put("/blogs/:id", authenticateToken, async (req, res) => {
  try {
    const blog = await Blog.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true });
    if (!blog) return res.status(404).json({ message: "Tapılmadı" });
    res.json(blog);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.delete("/blogs/:id", authenticateToken, async (req, res) => {
  try {
    const blog = await Blog.findByIdAndDelete(req.params.id);
    if (!blog) return res.status(404).json({ message: "Tapılmadı" });
    res.json({ message: "Silindi" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});








// ======================= PASSWORD RESET SCHEMA =======================
const passwordResetSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'Admin' },
  resetCode: { type: String, required: true },
  expiresAt: { type: Date, required: true },
  used: { type: Boolean, default: false }
});

const PasswordReset = mongoose.model("PasswordReset", passwordResetSchema);

// ======================= FORGOT PASSWORD - SEND CODE =======================
app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ success: false, message: "Email daxil edin" });
    }

    
    const admin = await Admin.findOne({ email });
    if (!admin) {
    
      return res.status(200).json({ 
        success: true, 
        message: "Əgər bu email qeydiyyatdan keçibsə, sıfırlama kodu göndəriləcək" 
      });
    }

    
    const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
    await PasswordReset.deleteMany({ userId: admin._id, used: false });


    await PasswordReset.create({
      userId: admin._id,
      resetCode: resetCode,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000), 
      used: false
    });

  
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Şifrə Sıfırlama Kodu - Admin Panel",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #667eea;">Şifrə Sıfırlama</h2>
          <p>Hörmətli ${admin.name},</p>
          <p>Şifrənizi sıfırlamaq üçün aşağıdaki kodu istifadə edin:</p>
          <div style="background-color: #f4f4f4; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
            ${resetCode}
          </div>
          <p style="color: #666;">Bu kod 10 dəqiqə ərzində etibarlıdır.</p>
          <p style="color: #999; font-size: 12px;">Əgər siz bu əməliyyatı tələb etməmisinizsə, bu emaili nəzərə almayın.</p>
        </div>
      `,
    };

    await transporter.sendMail(mailOptions);

    res.status(200).json({ 
      success: true, 
      message: "Sıfırlama kodu emailinizə göndərildi" 
    });

  } catch (error) {
    console.error("Forgot password error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Xəta baş verdi. Zəhmət olmasa yenidən cəhd edin" 
    });
  }
});

// ======================= VERIFY RESET CODE =======================
app.post("/api/auth/verify-reset-code", async (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res.status(400).json({ success: false, message: "Email və kod daxil edin" });
    }

    
    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(404).json({ success: false, message: "İstifadəçi tapılmadı" });
    }

    
    const resetRequest = await PasswordReset.findOne({
      userId: admin._id,
      resetCode: code,
      used: false,
      expiresAt: { $gt: new Date() }
    });

    if (!resetRequest) {
      return res.status(400).json({ 
        success: false, 
        message: "Kod yanlışdır və ya vaxtı keçib" 
      });
    }

    res.status(200).json({ 
      success: true, 
      message: "Kod təsdiqləndi",
      resetId: resetRequest._id
    });

  } catch (error) {
    console.error("Verify code error:", error);
    res.status(500).json({ success: false, message: "Xəta baş verdi" });
  }
});

// ======================= RESET PASSWORD =======================
app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;

    if (!email || !code || !newPassword) {
      return res.status(400).json({ 
        success: false, 
        message: "Bütün sahələri doldurun" 
      });
    }

 
    if (newPassword.length < 6) {
      return res.status(400).json({ 
        success: false, 
        message: "Şifrə ən azı 6 simvol olmalıdır" 
      });
    }

    const strongPasswordRegex = /^(?=.*[A-Z])(?=.*\d).{6,}$/;
    if (!strongPasswordRegex.test(newPassword)) {
      return res.status(400).json({ 
        success: false, 
        message: "Şifrə ən azı bir böyük hərf və bir rəqəm olmalıdır" 
      });
    }

    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(404).json({ success: false, message: "İstifadəçi tapılmadı" });
    }

    const resetRequest = await PasswordReset.findOne({
      userId: admin._id,
      resetCode: code,
      used: false,
      expiresAt: { $gt: new Date() }
    });

    if (!resetRequest) {
      return res.status(400).json({ 
        success: false, 
        message: "Kod yanlışdır və ya vaxtı keçib" 
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    admin.password = hashedPassword;
    await admin.save();

    resetRequest.used = true;
    await resetRequest.save();

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Şifrəniz Dəyişdirildi - Admin Panel",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #667eea;">Şifrə Dəyişdirildi</h2>
          <p>Hörmətli ${admin.name},</p>
          <p>Şifrəniz uğurla dəyişdirildi.</p>
          <p style="color: #999; font-size: 12px;">Əgər bu əməliyyatı siz həyata keçirməmisinizsə, dərhal bizimlə əlaqə saxlayın.</p>
        </div>
      `,
    };

    await transporter.sendMail(mailOptions);

    res.status(200).json({ 
      success: true, 
      message: "Şifrəniz uğurla dəyişdirildi" 
    });

  } catch (error) {
    console.error("Reset password error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Xəta baş verdi. Zəhmət olmasa yenidən cəhd edin" 
    });
  }
});

app.get("/api/admins", async (req, res) => {
  try {
    const admins = await Admin.find({}, "name email createdAt");
    res.json(admins);
  } catch (err) {
    res.status(500).json({ message: "Xəta baş verdi" });
  }
});

app.delete("/api/admins/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const deletedAdmin = await Admin.findByIdAndDelete(id);

    if (!deletedAdmin) {
      return res.status(404).json({ message: "Admin tapılmadı" });
    }

    res.json({ message: "Admin uğurla silindi", deletedAdmin });
  } catch (error) {
    res.status(500).json({ message: "Silinmə zamanı xəta baş verdi", error: error.message });
  }
});


const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server ${PORT} portunda işləyir`));





