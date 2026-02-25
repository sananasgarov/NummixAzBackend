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
  .connect(process.env.MONGO_URI)
  .then(() => console.log(" MongoDB connected"))
  .catch(() => console.log(" MongoDB connection failed"));

const JWT_SECRET =
  process.env.JWT_SECRET || "your_secret_key_here_change_in_production";

// ======================= ADMIN USER SCHEMA =======================
const adminSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

const Admin = mongoose.model("Admin", adminSchema);

// ======================= AUTH MIDDLEWARE =======================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ success: false, message: "Token tapılmadı" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res
        .status(403)
        .json({ success: false, message: "Token etibarsızdır" });
    }
    req.user = user;
    next();
  });
};

// ======================= REGISTER (DEACTIVATED) =======================
app.post("/api/auth/register", async (req, res) => {
  return res.status(403).json({
    success: false,
    message: "Yeni admin qeydiyyatı bağlıdır. Əlavə admin yaradıla bilməz.",
  });
});

// ======================= LOGIN =======================
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log("in login");
    if (!email || !password) {
      return res
        .status(400)
        .json({ success: false, message: "Email və şifrə daxil edin" });
    }

    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res
        .status(401)
        .json({ success: false, message: "Email və ya şifrə yanlışdır" });
    }

    const isPasswordValid = await bcrypt.compare(password, admin.password);
    if (!isPasswordValid) {
      return res
        .status(401)
        .json({ success: false, message: "Email və ya şifrə yanlışdır" });
    }

    const token = jwt.sign({ id: admin._id, email: admin.email }, JWT_SECRET, {
      expiresIn: "7d",
    });

    res.status(200).json({
      success: true,
      message: "Daxil olma uğurlu",
      token,
      user: {
        id: admin._id,
        name: admin.name,
        email: admin.email,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res
      .status(500)
      .json({ success: false, message: "Daxil olma zamanı xəta baş verdi" });
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
    const admin = await Admin.findById(req.user.id).select("-password");
    if (!admin) {
      return res
        .status(404)
        .json({ success: false, message: "İstifadəçi tapılmadı" });
    }
    res.json({ success: true, user: admin });
  } catch (error) {
    res.status(500).json({ success: false, message: "Xəta baş verdi" });
  }
});

// ======================= EMAIL CONFIGURATION =======================
const sendEmail = async (to, subject, html) => {
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: `Nummix <${process.env.EMAIL_FROM}>`,
      to,
      subject,
      html,
    }),
  });

  if (!response.ok) {
    const err = await response.text();
    throw new Error(err);
  }

  return response.json();
};

// ======================= CONTACT SCHEMA =======================
const contactSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email: { type: String, required: true },
  companyName: String,
  message: { type: String, required: true },
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
});

const Contact = mongoose.model("Contact", contactSchema);

// ======================= CONTACT API =======================
// GET all contacts
app.get("/contacts", authenticateToken, async (req, res) => {
  try {
    const contacts = await Contact.find().sort({ createdAt: -1 });
    res.json(contacts);
  } catch (error) {
    console.error("Get contacts error:", error);
    res.status(500).json({
      success: false,
      message: "Xəta baş verdi",
    });
  }
});

// GET single contact
app.get("/contacts/:id", authenticateToken, async (req, res) => {
  try {
    const contact = await Contact.findById(req.params.id);
    if (!contact) {
      return res.status(404).json({
        success: false,
        message: "Müraciət tapılmadı",
      });
    }
    res.json(contact);
  } catch (error) {
    console.error("Get contact error:", error);
    res.status(500).json({
      success: false,
      message: "Xəta baş verdi",
    });
  }
});

// POST new contact (from website)
app.post("/contact", async (req, res) => {
  try {
    const { fullName, email, companyName, message } = req.body;

    // Validation
    if (!fullName || !email || !message) {
      return res.status(400).json({
        success: false,
        message: "Zəhmət olmasa bütün vacib sahələri doldurun",
      });
    }

    // Save contact to database
    await Contact.create({
      fullName,
      email,
      companyName,
      message,
      read: false,
    });

    // Email notification disabled - keeping for future use if needed
    /* 
    // Admin notification email
    const mailOptions = {
      from: "no-reply@nummix.az",
      to: process.env.EMAIL_TO, // Admin email
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
      from: "no-reply@nummix.az",
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
    try {
      await Promise.all([
        sendEmail(process.env.EMAIL_TO, mailOptions.subject, mailOptions.html),
        sendEmail(email, autoReplyOptions.subject, autoReplyOptions.html)
      ]);
    } catch (err) {
      console.error("Email error ignored:", err.message);
    }
    */

    res.status(200).json({
      success: true,
      message: "Mesajınız uğurla göndərildi",
    });
  } catch (error) {
    console.error("Contact form error details:", {
      message: error.message,
      stack: error.stack,
      error: error,
    });
    res.status(500).json({
      success: false,
      message: "Sistem xətası baş verdi. Zəhmət olmasa yenidən cəhd edin.",
    });
  }
});

// PUT update contact (mark as read/unread or edit)
app.put("/contacts/:id", authenticateToken, async (req, res) => {
  try {
    const contact = await Contact.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    });
    if (!contact) {
      return res.status(404).json({
        success: false,
        message: "Müraciət tapılmadı",
      });
    }
    res.json(contact);
  } catch (error) {
    console.error("Update contact error:", error);
    res.status(400).json({
      success: false,
      message: "Müraciət yenilənə bilmədi",
    });
  }
});

// DELETE contact
app.delete("/contacts/:id", authenticateToken, async (req, res) => {
  try {
    const contact = await Contact.findByIdAndDelete(req.params.id);
    if (!contact) {
      return res.status(404).json({
        success: false,
        message: "Müraciət tapılmadı",
      });
    }
    res.json({
      success: true,
      message: "Müraciət silindi",
    });
  } catch (error) {
    console.error("Delete contact error:", error);
    res.status(500).json({
      success: false,
      message: "Müraciət silinə bilmədi",
    });
  }
});

// ======================= TEAM =======================
const teamSchema = new mongoose.Schema({
  queueNumber: Number,
  image: String,
  name: String,
  position: String,
  description: String,
  linkedin: String,
  email: String,
});
teamSchema.pre("save", async function (next) {
  if (this.queueNumber != null) return next();

  const lastTeam = await mongoose.model("Team").findOne().sort("-queueNumber");

  this.queueNumber = lastTeam ? lastTeam.queueNumber + 1 : 1;

  next();
});

const Team = mongoose.model("Team", teamSchema);

app.get("/team", async (req, res) => {
  try {
    const teams = await Team.find().sort({ queueNumber: 1 });
    res.json(teams);
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
app.put("/team/reorder-queue", authenticateToken, async (req, res) => {
  try {
    const { items } = req.body;

    const bulkOps = items.map((item) => ({
      updateOne: {
        filter: { _id: item._id },
        update: { $set: { queueNumber: item.queueNumber } },
      },
    }));

    await Team.bulkWrite(bulkOps);

    res.json({ message: "Order updated successfully" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
app.put("/team/:id", authenticateToken, async (req, res) => {
  try {
    const team = await Team.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    });
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
const blogSchema = new mongoose.Schema(
  {
    queueNumber: Number,
    title: String,
    category: String,
    excerpt: String,
    coverImage: String,
    date: String,
    readTime: String,
    author: {
      name: String,
      initials: String,
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

    result: String,
  },
  { timestamps: true },
);
blogSchema.pre("save", async function (next) {
  if (this.queueNumber != null) return next();

  const lastBlog = await mongoose.model("Blog").findOne().sort("-queueNumber");

  this.queueNumber = lastBlog ? lastBlog.queueNumber + 1 : 1;

  next();
});
const Blog = mongoose.model("Blog", blogSchema);

app.get("/blogs", async (req, res) => {
  try {
    const blogs = await Blog.find().sort({ queueNumber: 1 });
    res.json(blogs);
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

app.put("/blogs/reorder-queue", authenticateToken, async (req, res) => {
  try {
    const { items } = req.body;

    const bulkOps = items.map((item) => ({
      updateOne: {
        filter: { _id: item._id },
        update: { $set: { queueNumber: item.queueNumber } },
      },
    }));

    await Blog.bulkWrite(bulkOps);

    res.json({ message: "Order updated successfully" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.put("/blogs/:id", authenticateToken, async (req, res) => {
  try {
    const blog = await Blog.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    });
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
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: "Admin",
  },
  resetCode: { type: String, required: true },
  expiresAt: { type: Date, required: true },
  used: { type: Boolean, default: false },
});

const PasswordReset = mongoose.model("PasswordReset", passwordResetSchema);

// ======================= FORGOT PASSWORD - SEND CODE =======================
app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res
        .status(400)
        .json({ success: false, message: "Zəhmət olmasa email daxil edin" });
    }

    const admin = await Admin.findOne({ email });

    // Security: Always return success even if email not found to prevent enumeration
    if (!admin) {
      return res.status(200).json({
        success: true,
        message: "Email qeydiyyatlıdırsa, təsdiq kodu göndəriləcək",
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
      used: false,
    });

    const mailOptions = {
      from: "no-reply@nummix.az",
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

    await sendEmail(
      process.env.EMAIL_TO,
      mailOptions.subject,
      mailOptions.html,
    );

    res.status(200).json({
      success: true,
      message: "Təsdiq kodu email ünvanınıza göndərildi",
    });
  } catch (error) {
    console.error("Forgot password error:", error);
    res.status(500).json({
      success: false,
      message: "Xəta baş verdi. Zəhmət olmasa bir az sonra yenidən cəhd edin",
    });
  }
});

// ======================= VERIFY RESET CODE =======================
app.post("/api/auth/verify-reset-code", async (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res
        .status(400)
        .json({ success: false, message: "Email və kod daxil edin" });
    }

    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res
        .status(404)
        .json({ success: false, message: "İstifadəçi tapılmadı" });
    }

    const resetRequest = await PasswordReset.findOne({
      userId: admin._id,
      resetCode: code,
      used: false,
      expiresAt: { $gt: new Date() },
    });

    if (!resetRequest) {
      return res.status(400).json({
        success: false,
        message: "Kod yanlışdır və ya müddəti bitib",
      });
    }

    res.status(200).json({
      success: true,
      message: "Kod təsdiqləndi",
      resetId: resetRequest._id,
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
        message: "Bütün sahələri doldurun",
      });
    }

    // Password validation - Minimum 6 characters
    if (newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Şifrə ən azı 6 simvol olmalıdır",
      });
    }

    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res
        .status(404)
        .json({ success: false, message: "İstifadəçi tapılmadı" });
    }

    // Verify code validity
    const resetRequest = await PasswordReset.findOne({
      userId: admin._id,
      resetCode: code,
      used: false,
      expiresAt: { $gt: new Date() },
    });

    if (!resetRequest) {
      return res.status(400).json({
        success: false,
        message: "Kod yanlışdır və ya müddəti bitib",
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
      from: "no-reply@nummix.az",
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

    await sendEmail(mailOptions.to, mailOptions.subject, mailOptions.html);

    res.status(200).json({
      success: true,
      message: "Şifrəniz uğurla yeniləndi",
    });
  } catch (error) {
    console.error("Reset password error:", error);
    res.status(500).json({
      success: false,
      message: "Xəta baş verdi. Zəhmət olmasa yenidən cəhd edin",
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
    res
      .status(500)
      .json({ message: "Silinmə zamanı xəta baş verdi", error: error.message });
  }
});

const PORT = process.env.PORT;
app.listen(PORT, () => console.log(`Server ${PORT} portunda işləyir`));

// ======================= MENTORS =======================
const mentorSchema = new mongoose.Schema({
  queueNumber: Number,
  image: String,
  name: String,
  position: String,
  description: String,
  linkedin: String,
  email: String,
});

mentorSchema.pre("save", async function (next) {
  if (this.queueNumber != null) return next();

  const lastMentor = await mongoose
    .model("Mentor")
    .findOne()
    .sort("-queueNumber");

  this.queueNumber = lastMentor ? lastMentor.queueNumber + 1 : 1;

  next();
});
const Mentor = mongoose.model("Mentor", mentorSchema);
app.get("/mentor", async (req, res) => {
  try {
    const mentors = await Mentor.find().sort({ queueNumber: 1 });
    res.json(mentors);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.put("/mentor/reorder-queue", authenticateToken, async (req, res) => {
  try {
    const { items } = req.body;

    const bulkOps = items.map((item) => ({
      updateOne: {
        filter: { _id: item._id },
        update: { $set: { queueNumber: item.queueNumber } },
      },
    }));

    await Mentor.bulkWrite(bulkOps);

    res.json({ message: "Order updated successfully" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.put("/mentor/:id", authenticateToken, async (req, res) => {
  try {
    const mentor = await Mentor.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    });
    if (!mentor) return res.status(404).json({ message: "Tapılmadı" });
    res.json(mentor);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});
app.post("/mentor", authenticateToken, async (req, res) => {
  try {
    const mentor = await Mentor.create(req.body);
    res.status(201).json(mentor);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.delete("/mentor/:id", authenticateToken, async (req, res) => {
  try {
    const mentor = await Mentor.findByIdAndDelete(req.params.id);
    if (!mentor) return res.status(404).json({ message: "Tapılmadı" });
    res.json({ message: "Silindi" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

///===========================Partners=============================
const partnersSchema = new mongoose.Schema({
  queueNumber: Number,
  name: String,
  description: String,
  image: String,
});

partnersSchema.pre("save", async function (next) {
  if (this.queueNumber != null) return next();

  const lastPartner = await mongoose
    .model("Partner")
    .findOne()
    .sort("-queueNumber");

  this.queueNumber = lastPartner ? lastPartner.queueNumber + 1 : 1;

  next();
});
const Partner = mongoose.model("Partner", partnersSchema);

app.get("/partner", async (req, res) => {
  try {
    const partners = await Partner.find().sort({ queueNumber: 1 });
    res.json(partners);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.put("/partner/reorder-queue", authenticateToken, async (req, res) => {
  try {
    const { items } = req.body;

    const bulkOps = items.map((item) => ({
      updateOne: {
        filter: { _id: item._id },
        update: { $set: { queueNumber: item.queueNumber } },
      },
    }));

    await Partner.bulkWrite(bulkOps);

    res.json({ message: "Order updated successfully" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.put("/partner/:id", authenticateToken, async (req, res) => {
  try {
    const partner = await Partner.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    });
    if (!partner) return res.status(404).json({ message: "Tapılmadı" });
    res.json(partner);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.post("/partner", authenticateToken, async (req, res) => {
  try {
    const partner = await Partner.create(req.body);
    res.status(201).json(partner);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.delete("/partner/:id", authenticateToken, async (req, res) => {
  try {
    const partner = await Partner.findByIdAndDelete(req.params.id);
    if (!partner) return res.status(404).json({ message: "Tapılmadı" });
    res.json({ message: "Silindi" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

///===========================Customer=============================
const customerSchema = new mongoose.Schema({
  queueNumber: Number,
  name: String,
  description: String,
  image: String,
});

customerSchema.pre("save", async function (next) {
  if (this.queueNumber != null) return next();

  const lastDetail = await mongoose
    .model("Customer")
    .findOne()
    .sort("-queueNumber");

  this.queueNumber = lastDetail ? lastDetail.queueNumber + 1 : 1;

  next();
});
const Customer = mongoose.model("Customer", customerSchema);

app.post("/customer", authenticateToken, async (req, res) => {
  try {
    const detail = await Customer.create(req.body);
    res.status(201).json(detail);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.get("/customer", async (req, res) => {
  try {
    const customer = await Customer.find().sort({ queueNumber: 1 });
    res.json(customer);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
app.put("/customer/:id", authenticateToken, async (req, res) => {
  try {
    const customer = await Customer.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    });
    if (!customer) return res.status(404).json({ message: "Tapılmadı" });
    res.json(customer);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});
app.put("/customer/reorder-queue", authenticateToken, async (req, res) => {
  try {
    const { items } = req.body;

    const bulkOps = items.map((item) => ({
      updateOne: {
        filter: { _id: item._id },
        update: { $set: { queueNumber: item.queueNumber } },
      },
    }));

    await Customer.bulkWrite(bulkOps);

    res.json({ message: "Order updated successfully" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.delete("/customer/:id", authenticateToken, async (req, res) => {
  try {
    const customer = await Customer.findByIdAndDelete(req.params.id);
    if (!customer) return res.status(404).json({ message: "Tapılmadı" });
    res.json({ message: "Silindi" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

///===========================Product=============================
const productSchema = new mongoose.Schema({
  queueNumber: Number,
  name: String,
  image: String,
});

productSchema.pre("save", async function (next) {
  if (this.queueNumber != null) return next();

  const lastDetail = await mongoose
    .model("Product")
    .findOne()
    .sort("-queueNumber");

  this.queueNumber = lastDetail ? lastDetail.queueNumber + 1 : 1;

  next();
});
const Product = mongoose.model("Product", productSchema);

app.get("/product", async (req, res) => {
  try {
    const product = await Product.find().sort({ queueNumber: 1 });
    res.json(product);
  } catch (error) {
    res.status(500).json({ message: err.message });
  }
});

app.post("/product", authenticateToken, async (req, res) => {
  try {
    const product = await Product.create(req.body);
    res.status(201).json(product);
  } catch (error) {
    res.status(400).json({ message: err.message });
  }
});

app.put("/product/:id", authenticateToken, async (req, res) => {
  try {
    const product = await Product.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    });
    if (!product) return res.status(404).json({ message: "Tapılmadı" });
    res.json(product);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});
app.put("/product/reorder-queue", authenticateToken, async (req, res) => {
  try {
    const { items } = req.body;

    const bulkOps = items.map((item) => ({
      updateOne: {
        filter: { _id: item._id },
        update: { $set: { queueNumber: item.queueNumber } },
      },
    }));

    await Product.bulkWrite(bulkOps);

    res.json({ message: "Order updated successfully" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.delete("/product/:id", authenticateToken, async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);
    if (!product) return res.status(404).json({ message: "Tapılmadı" });
    res.json({ message: "Silindi" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

///===========================ContactDetail=============================
const contactDetailSchema = new mongoose.Schema({
  queueNumber: Number,

  nameAz: String,
  nameRu: String,
  nameEn: String,

  descriptionAz: String,
  descriptionRu: String,
  descriptionEn: String,

  icon: String,
});
contactDetailSchema.pre("save", async function (next) {
  if (this.queueNumber != null) return next();

  const lastDetail = await mongoose
    .model("ContactDetail")
    .findOne()
    .sort("-queueNumber");

  this.queueNumber = lastDetail ? lastDetail.queueNumber + 1 : 1;

  next();
});
const ContactDetail = mongoose.model("ContactDetail", contactDetailSchema);

app.post("/contactDetail", authenticateToken, async (req, res) => {
  try {
    const detail = await ContactDetail.create(req.body);
    res.status(201).json(detail);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.get("/contactDetail", async (req, res) => {
  try {
    const contactDetail = await ContactDetail.find().sort({ queueNumber: 1 });
    res.json(contactDetail);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
app.put("/contactDetail/:id", authenticateToken, async (req, res) => {
  try {
    const contactDetail = await ContactDetail.findByIdAndUpdate(
      req.params.id,
      req.body,
      {
        new: true,
        runValidators: true,
      },
    );
    if (!contactDetail) return res.status(404).json({ message: "Tapılmadı" });
    res.json(contactDetail);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});
app.put("/contactDetail/reorder-queue", authenticateToken, async (req, res) => {
  try {
    const { items } = req.body;

    const bulkOps = items.map((item) => ({
      updateOne: {
        filter: { _id: item._id },
        update: { $set: { queueNumber: item.queueNumber } },
      },
    }));

    await ContactDetail.bulkWrite(bulkOps);

    res.json({ message: "Order updated successfully" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
app.delete("/contactDetail/:id", authenticateToken, async (req, res) => {
  try {
    const contactDetail = await ContactDetail.findByIdAndDelete(req.params.id);
    if (!contactDetail) return res.status(404).json({ message: "Tapılmadı" });
    res.json({ message: "Silindi" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//==================== Page======================

const pageTranslationSchema = new mongoose.Schema(
  {
    header: {
      type: String,
      required: true,
      trim: true,
      minlength: 1,
      maxlength: 500,
    },
    paragraph: {
      type: String,
      required: true,
      trim: true,
      minlength: 1,
      maxlength: 5000,
    },
  },
  { _id: false },
);

const pageSchema = new mongoose.Schema(
  {
    pageName: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      match: /^[a-z0-9-]+$/,
    },
    translations: {
      type: Map,
      of: pageTranslationSchema,
      default: {},
    },
  },
  { timestamps: true },
);

pageSchema.index({ pageName: 1 });

const Page = mongoose.model("Page", pageSchema);

// app.post("/page", async (req, res) => {
//   try {
//     const { pageName } = req.body;

//     if (!pageName)
//       return res.status(400).json({ message: "Page name is required" });

//     const page = await Page.create({ pageName });
//     res.status(201).json(page);
//   } catch (err) {
//     res.status(400).json({ message: err.message });
//   }
// });

app.get("/page/:pageName", async (req, res) => {
  try {
    const { pageName } = req.params;
    const { locale = "en" } = req.query;

    const page = await Page.findOne({ pageName });
    if (!page) return res.status(404).json({ message: "Page not found" });

    const translation =
      page.translations.get(locale) || page.translations.get("en");

    if (!translation)
      return res.status(404).json({ message: "Translation not found" });

    res.json({
      pageName: page.pageName,
      locale,
      header: translation.header,
      paragraph: translation.paragraph,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.put("/page/:pageName/translation", async (req, res) => {
  try {
    const { pageName } = req.params;
    const { locale, header, paragraph } = req.body;

    if (!locale || !header || !paragraph)
      return res.status(400).json({ message: "Missing fields" });

    const page = await Page.findOneAndUpdate(
      { pageName },
      { $set: { [`translations.${locale}`]: { header, paragraph } } },
      { new: true, runValidators: true },
    );

    if (!page) return res.status(404).json({ message: "Page not found" });

    res.json({ success: true, page });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.delete(
  "/page/:pageName/translation/:locale",
  authenticateToken,
  async (req, res) => {
    try {
      const { pageName, locale } = req.params;

      const page = await Page.findOne({ pageName });
      if (!page) return res.status(404).json({ message: "Page not found" });

      page.translations.delete(locale);
      await page.save();

      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ message: err.message });
    }
  },
);

app.delete("/page/:pageName", authenticateToken, async (req, res) => {
  try {
    const { pageName } = req.params;

    const page = await Page.findOneAndDelete({ pageName });
    if (!page) return res.status(404).json({ message: "Page not found" });

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//======================== Feature ==========
const featureSchema = new mongoose.Schema({
  queueNumber: Number,

  titleAz: String,
  titleRu: String,
  titleEn: String,

  descriptionAz: String,
  descriptionRu: String,
  descriptionEn: String,

  image: String,
});
featureSchema.pre("save", async function (next) {
  if (this.queueNumber != null) return next();

  const lastFeature = await mongoose
    .model("Feature")
    .findOne()
    .sort("-queueNumber");

  this.queueNumber = lastFeature ? lastFeature.queueNumber + 1 : 1;

  next();
});

const Feature = mongoose.model("Feature", featureSchema);
app.get("/features", async (req, res) => {
  try {
    const features = await Feature.find().sort({ queueNumber: 1 });
    res.json(features);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
app.post("/features", authenticateToken, async (req, res) => {
  try {
    const feature = await Feature.create(req.body);
    res.status(201).json(feature);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.put("/features/reorder-queue", authenticateToken, async (req, res) => {
  try {
    const { items } = req.body;

    const bulkOps = items.map((item) => ({
      updateOne: {
        filter: { _id: item._id },
        update: { $set: { queueNumber: item.queueNumber } },
      },
    }));

    await Feature.bulkWrite(bulkOps);

    res.json({ message: "Order updated successfully" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
app.put("/features/:id", authenticateToken, async (req, res) => {
  try {
    const feature = await Feature.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    });

    if (!feature) {
      return res.status(404).json({ message: "Tapılmadı" });
    }

    res.json(feature);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.delete("/features/:id", authenticateToken, async (req, res) => {
  try {
    const feature = await Feature.findByIdAndDelete(req.params.id);

    if (!feature) {
      return res.status(404).json({ message: "Tapılmadı" });
    }

    res.json({ message: "Silindi" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//==================== Culture ======================

const cultureSchema = new mongoose.Schema({
  queueNumber: Number,

  titleAz: String,
  titleRu: String,
  titleEn: String,

  descriptionAz: String,
  descriptionRu: String,
  descriptionEn: String,

  image: String,
});
cultureSchema.pre("save", async function (next) {
  if (this.queueNumber != null) return next();

  const lastCulture = await mongoose
    .model("Culture")
    .findOne()
    .sort("-queueNumber");

  this.queueNumber = lastCulture ? lastCulture.queueNumber + 1 : 1;

  next();
});

const Culture = mongoose.model("Culture", cultureSchema);
app.get("/cultures", async (req, res) => {
  try {
    const cultures = await Culture.find().sort({ queueNumber: 1 });
    res.json(cultures);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
app.post("/cultures", authenticateToken, async (req, res) => {
  try {
    const cultures = await Culture.create(req.body);
    res.status(201).json(cultures);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});
app.put("/cultures/reorder-queue", authenticateToken, async (req, res) => {
  try {
    const { items } = req.body;

    const bulkOps = items.map((item) => ({
      updateOne: {
        filter: { _id: item._id },
        update: { $set: { queueNumber: item.queueNumber } },
      },
    }));

    await Culture.bulkWrite(bulkOps);

    res.json({ message: "Order updated successfully" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
app.put("/cultures/:id", authenticateToken, async (req, res) => {
  try {
    const culture = await Culture.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    });

    if (!culture) {
      return res.status(404).json({ message: "Tapılmadı" });
    }

    res.json(culture);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.delete("/cultures/:id", authenticateToken, async (req, res) => {
  try {
    const culture = await Culture.findByIdAndDelete(req.params.id);

    if (!culture) {
      return res.status(404).json({ message: "Tapılmadı" });
    }

    res.json({ message: "Silindi" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
//==================== AboutUs ======================

const aboutUsSchema = new mongoose.Schema({
  queueNumber: Number,

  storyAz: String,
  storyRu: String,
  storyEn: String,

  noteAz: String,
  noteRu: String,
  noteEn: String,

  image: String,
});
aboutUsSchema.pre("save", async function (next) {
  if (this.queueNumber != null) return next();

  const lastAbout = await mongoose
    .model("AboutUs")
    .findOne()
    .sort("-queueNumber");

  this.queueNumber = lastAbout ? lastAbout.queueNumber + 1 : 1;

  next();
});

const AboutUs = mongoose.model("AboutUs", aboutUsSchema);
app.get("/aboutUs", async (req, res) => {
  try {
    const about = await AboutUs.find().sort({ queueNumber: 1 });
    res.json(about);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
app.post("/aboutUs", authenticateToken, async (req, res) => {
  try {
    const about = await AboutUs.create(req.body);
    res.status(201).json(about);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});
app.put("/aboutUs/reorder-queue", authenticateToken, async (req, res) => {
  try {
    const { items } = req.body;

    const bulkOps = items.map((item) => ({
      updateOne: {
        filter: { _id: item._id },
        update: { $set: { queueNumber: item.queueNumber } },
      },
    }));

    await AboutUs.bulkWrite(bulkOps);

    res.json({ message: "Order updated successfully" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
app.put("/aboutUs/:id", authenticateToken, async (req, res) => {
  try {
    const about = await AboutUs.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    });

    if (!about) {
      return res.status(404).json({ message: "Tapılmadı" });
    }

    res.json(about);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.delete("/aboutUs/:id", authenticateToken, async (req, res) => {
  try {
    const about = await AboutUs.findByIdAndDelete(req.params.id);

    if (!about) {
      return res.status(404).json({ message: "Tapılmadı" });
    }

    res.json({ message: "Silindi" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//==================== Stat ======================

const statSchema = new mongoose.Schema({
  queueNumber: Number,

  count: Number,
  titleAz: String,
  titleRu: String,
  titleEn: String,

  image: String,
});
statSchema.pre("save", async function (next) {
  if (this.queueNumber != null) return next();

  const lastStat = await mongoose.model("Stat").findOne().sort("-queueNumber");

  this.queueNumber = lastStat ? lastStat.queueNumber + 1 : 1;

  next();
});

const Stat = mongoose.model("Stat", statSchema);
app.get("/stats", async (req, res) => {
  try {
    const stat = await Stat.find().sort({ queueNumber: 1 });
    res.json(stat);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
app.post("/stats", authenticateToken, async (req, res) => {
  try {
    const stat = await Stat.create(req.body);
    res.status(201).json(stat);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});
app.put("/stats/reorder-queue", authenticateToken, async (req, res) => {
  try {
    const { items } = req.body;

    const bulkOps = items.map((item) => ({
      updateOne: {
        filter: { _id: item._id },
        update: { $set: { queueNumber: item.queueNumber } },
      },
    }));

    await Stat.bulkWrite(bulkOps);

    res.json({ message: "Order updated successfully" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
app.put("/stats/:id", authenticateToken, async (req, res) => {
  try {
    const stat = await Stat.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    });

    if (!stat) {
      return res.status(404).json({ message: "Tapılmadı" });
    }

    res.json(stat);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.delete("/stats/:id", authenticateToken, async (req, res) => {
  try {
    const stat = await Stat.findByIdAndDelete(req.params.id);

    if (!stat) {
      return res.status(404).json({ message: "Tapılmadı" });
    }

    res.json({ message: "Silindi" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//==================== Value ======================

const valueSchema = new mongoose.Schema({
  queueNumber: Number,

  titleAz: String,
  titleRu: String,
  titleEn: String,

  descriptionAz: String,
  descriptionRu: String,
  descriptionEn: String,
  initial: String,
});
valueSchema.pre("save", async function (next) {
  if (this.queueNumber != null) return next();

  const lastValue = await mongoose
    .model("Value")
    .findOne()
    .sort("-queueNumber");

  this.queueNumber = lastValue ? lastValue.queueNumber + 1 : 1;

  next();
});
const Value = mongoose.model("Value", valueSchema);
app.get("/values", async (req, res) => {
  try {
    const value = await Value.find().sort({ queueNumber: 1 });
    res.json(value);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
app.post("/values", authenticateToken, async (req, res) => {
  try {
    const value = await Value.create(req.body);
    res.status(201).json(value);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});
app.put("/values/reorder-queue", authenticateToken, async (req, res) => {
  try {
    const { items } = req.body;

    const bulkOps = items.map((item) => ({
      updateOne: {
        filter: { _id: item._id },
        update: { $set: { queueNumber: item.queueNumber } },
      },
    }));

    await Value.bulkWrite(bulkOps);

    res.json({ message: "Order updated successfully" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
app.put("/values/:id", authenticateToken, async (req, res) => {
  try {
    const value = await Value.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    });

    if (!value) {
      return res.status(404).json({ message: "Tapılmadı" });
    }

    res.json(value);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.delete("/values/:id", authenticateToken, async (req, res) => {
  try {
    const value = await Value.findByIdAndDelete(req.params.id);

    if (!value) {
      return res.status(404).json({ message: "Tapılmadı" });
    }

    res.json({ message: "Silindi" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//==================== Faq ======================

const faqSchema = new mongoose.Schema({
  queueNumber: Number,

  questionAz: String,
  questionRu: String,
  questionEn: String,

  answerAz: String,
  answerRu: String,
  answerEn: String,
});
faqSchema.pre("save", async function (next) {
  if (this.queueNumber != null) return next();

  const lastFaq = await mongoose.model("Faq").findOne().sort("-queueNumber");

  this.queueNumber = lastFaq ? lastFaq.queueNumber + 1 : 1;

  next();
});
const Faq = mongoose.model("Faq", faqSchema);
app.get("/faqs", async (req, res) => {
  try {
    const faq = await Faq.find().sort({ queueNumber: 1 });
    res.json(faq);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
app.post("/faqs", authenticateToken, async (req, res) => {
  try {
    const faq = await Faq.create(req.body);
    res.status(201).json(faq);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});
app.put("/faqs/reorder-queue", authenticateToken, async (req, res) => {
  try {
    const { items } = req.body;

    const bulkOps = items.map((item) => ({
      updateOne: {
        filter: { _id: item._id },
        update: { $set: { queueNumber: item.queueNumber } },
      },
    }));

    await Faq.bulkWrite(bulkOps);

    res.json({ message: "Order updated successfully" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
app.put("/faqs/:id", authenticateToken, async (req, res) => {
  try {
    const faq = await Faq.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    });

    if (!faq) {
      return res.status(404).json({ message: "Tapılmadı" });
    }

    res.json(faq);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.delete("/faqs/:id", authenticateToken, async (req, res) => {
  try {
    const faq = await Faq.findByIdAndDelete(req.params.id);

    if (!faq) {
      return res.status(404).json({ message: "Tapılmadı" });
    }

    res.json({ message: "Silindi" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
