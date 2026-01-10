import express from "express";
import nodemailer from "nodemailer";
import cors from "cors";
import dotenv from "dotenv";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();

app.use(cors());
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

// ======================= EMAIL CONFIGURATION =======================
const transporter = nodemailer.createTransport({
  host: "smtp.resend.com",
  port: 587,
  secure: false,
  auth: {
    user: "resend",
    pass: process.env.RESEND_API_KEY,
  },
});

// Transporter connection verification
transporter.verify((error, success) => {
  if (error) {
    console.log("Email server connection error:", error);
  } else {
    console.log("Email server is ready to take our messages");
  }
});

// ======================= CONTACT API =======================
app.post("/api/contact", async (req, res) => {
  try {
    const { fullName, email, companyName, message } = req.body;

    // Validation
    if (!fullName || !email || !message) {
      return res.status(400).json({ 
        success: false, 
        message: "Zəhmət olmasa bütün vacib sahələri doldurun" 
      });
    }

    // Admin notification email
    const mailOptions = {
      from: "onboarding@resend.dev",
      to: "nummixaz@gmail.com", // Admin email
      subject: `Nummix - Yeni Müraciət: ${fullName}`,
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px; border: 1px solid #eee; border-radius: 5px;">
          <h2 style="color: #333;">Yeni Müştəri Müraciəti</h2>
          <hr style="border: 0; border-top: 1px solid #eee;" />
          <p><strong>Ad Soyad:</strong> ${fullName}</p>
          <p><strong>Email:</strong> <a href="mailto:${email}">${email}</a></p>
          ${companyName ? `<p><strong>Şirkət:</strong> ${companyName}</p>` : ""}
          <p><strong>Mesaj:</strong></p>
          <div style="background-color: #f9f9f9; padding: 10px; border-radius: 4px;">
            ${message}
          </div>
        </div>
      `,
    };

    // Auto-reply to user
    const autoReplyOptions = {
      from: "onboarding@resend.dev",
      to: email,
      subject: "Müraciətiniz Qəbul Edildi - Nummix",
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px;">
          <h2 style="color: #4A90E2;">Hörmətli ${fullName},</h2>
          <p>Müraciətiniz bizə çatdı. Sizinlə ən qısa zamanda əlaqə saxlayacağıq.</p>
          <p>Təşəkkür edirik!</p>
          <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;" />
          <p style="color: #888; font-size: 12px;">Bu avtomatik mesajdır, xahiş edirik cavab yazmayın.</p>
        </div>
      `,
    };

    // Send emails in parallel
    await Promise.all([
      transporter.sendMail(mailOptions),
      transporter.sendMail(autoReplyOptions)
    ]);

    res.status(200).json({ 
      success: true, 
      message: "Mesajınız uğurla göndərildi" 
    });

  } catch (error) {
    console.error("Contact form error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Sistem xətası baş verdi. Zəhmət olmasa yenidən cəhd edin." 
    });
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
      return res.status(400).json({ success: false, message: "Zəhmət olmasa email daxil edin" });
    }

    const admin = await Admin.findOne({ email });
    
    // Security: Always return success even if email not found to prevent enumeration
    if (!admin) {
      return res.status(200).json({ 
        success: true, 
        message: "Email qeydiyyatlıdırsa, təsdiq kodu göndəriləcək" 
      });
    }

    // Generate 6 digit code
    const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Clear old codes
    await PasswordReset.deleteMany({ userId: admin._id, used: false });

    // Save new code
    await PasswordReset.create({
      userId: admin._id,
      resetCode: resetCode,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
      used: false
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Şifrə Sıfırlama Kodu - Admin Panel",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
          <h2 style="color: #4F46E5; text-align: center;">Şifrə Sıfırlama Tələbi</h2>
          <p>Hörmətli ${admin.name},</p>
          <p>Hesabınız üçün şifrə sıfırlama tələbi aldıq. Aşağıdakı kodu istifadə edərək şifrənizi yeniləyə bilərsiniz:</p>
          
          <div style="background-color: #f3f4f6; padding: 15px; text-align: center; border-radius: 6px; margin: 25px 0;">
            <span style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #111827;">${resetCode}</span>
          </div>

          <p style="color: #666; font-size: 14px;">⚠️ Bu kod <strong>10 dəqiqə</strong> ərzində etibarlıdır.</p>
          <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;" />
          <p style="color: #999; font-size: 12px; text-align: center;">Əgər bu əməliyyatı siz etməmisinizsə, bu mesajı lütfən ignor edin.</p>
        </div>
      `,
    };

    await transporter.sendMail(mailOptions);

    res.status(200).json({ 
      success: true, 
      message: "Təsdiq kodu email ünvanınıza göndərildi" 
    });

  } catch (error) {
    console.error("Forgot password error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Xəta baş verdi. Zəhmət olmasa bir az sonra yenidən cəhd edin" 
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
        message: "Kod yanlışdır və ya müddəti bitib" 
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

    // Password validation - Minimum 6 characters
    if (newPassword.length < 6) {
      return res.status(400).json({ 
        success: false, 
        message: "Şifrə ən azı 6 simvol olmalıdır" 
      });
    }

    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(404).json({ success: false, message: "İstifadəçi tapılmadı" });
    }

    // Verify code validity
    const resetRequest = await PasswordReset.findOne({
      userId: admin._id,
      resetCode: code,
      used: false,
      expiresAt: { $gt: new Date() }
    });

    if (!resetRequest) {
      return res.status(400).json({ 
        success: false, 
        message: "Kod yanlışdır və ya müddəti bitib" 
      });
    }

    // Update password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    admin.password = hashedPassword;
    await admin.save();

    // Mark code as used
    resetRequest.used = true;
    await resetRequest.save();

    // Send confirmation email
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Şifrəniz Uğurla Dəyişdirildi",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
          <h2 style="color: #10B981; text-align: center;">Şifrə Yeniləndi</h2>
          <p>Hörmətli ${admin.name},</p>
          <p>Sizin hesabınızın şifrəsi uğurla dəyişdirildi. Artıq yeni şifrənizlə giriş edə bilərsiniz.</p>
          <div style="text-align: center; margin: 30px 0;">
            <p style="background-color: #ECFDF5; color: #059669; padding: 10px; display: inline-block; border-radius: 4px;">Əməliyyat uğurla tamamlandı</p>
          </div>
          <p style="color: #999; font-size: 12px; text-align: center;">Əgər bu əməliyyatı siz etməmisinizsə, dərhal bizimlə əlaqə saxlayın.</p>
        </div>
      `,
    };

    await transporter.sendMail(mailOptions);

    res.status(200).json({ 
      success: true, 
      message: "Şifrəniz uğurla yeniləndi" 
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


const PORT = process.env.PORT;
app.listen(PORT, () => console.log(`Server ${PORT} portunda işləyir`));





