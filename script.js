// Mobile Navigation Toggle
const hamburger = document.querySelector('.hamburger');
const navMenu = document.querySelector('.nav-menu');

hamburger.addEventListener('click', () => {
    navMenu.classList.toggle('active');
});

// Close mobile menu when clicking on a link
document.querySelectorAll('.nav-menu a').forEach(link => {
    link.addEventListener('click', () => {
        navMenu.classList.remove('active');
    });
});

// Smooth scrolling for navigation links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            const offsetTop = target.offsetTop - 70;
            window.scrollTo({
                top: offsetTop,
                behavior: 'smooth'
            });
        }
    });
});

// Navbar background change on scroll
window.addEventListener('scroll', () => {
    const navbar = document.querySelector('.navbar');
    if (window.scrollY > 50) {
        navbar.classList.add('scrolled');
    } else {
        navbar.classList.remove('scrolled');
    }
});

// Intersection Observer for fade-in animations
const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px'
};

const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.style.opacity = '1';
            entry.target.style.transform = 'translateY(0)';
        }
    });
}, observerOptions);

// Observe all sections for animation
document.querySelectorAll('section').forEach(section => {
    section.style.opacity = '0';
    section.style.transform = 'translateY(20px)';
    section.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
    observer.observe(section);
});

// Add animation to timeline items
document.querySelectorAll('.timeline-item').forEach((item, index) => {
    item.style.opacity = '0';
    item.style.transform = 'translateX(-20px)';
    item.style.transition = `opacity 0.6s ease ${index * 0.1}s, transform 0.6s ease ${index * 0.1}s`;
    observer.observe(item);
});

// Add animation to cards
document.querySelectorAll('.cert-card, .skill-category, .achievement-card, .education-card').forEach((card, index) => {
    card.style.opacity = '0';
    card.style.transform = 'translateY(20px)';
    card.style.transition = `opacity 0.6s ease ${index * 0.05}s, transform 0.6s ease ${index * 0.05}s`;
    observer.observe(card);
});

// Parallax effect for hero section
window.addEventListener('scroll', () => {
    const scrolled = window.pageYOffset;
    const hero = document.querySelector('.hero');
    if (hero) {
        hero.style.transform = `translateY(${scrolled * 0.5}px)`;
        hero.style.opacity = 1 - (scrolled / 600);
    }
});

// Dynamic typing effect for hero subtitle
const subtitle = document.querySelector('.hero-subtitle');
if (subtitle) {
    const text = subtitle.textContent;
    subtitle.textContent = '';
    let i = 0;
    
    const typeWriter = () => {
        if (i < text.length) {
            subtitle.textContent += text.charAt(i);
            i++;
            setTimeout(typeWriter, 100);
        }
    };
    
    setTimeout(typeWriter, 500);
}

// Add floating animation to stat cards
const statCards = document.querySelectorAll('.stat-card');
statCards.forEach((card, index) => {
    card.style.animationDelay = `${index * 0.2}s`;
});

// Glowing cursor effect
document.addEventListener('mousemove', (e) => {
    const glow = document.createElement('div');
    glow.className = 'cursor-glow';
    glow.style.left = e.pageX + 'px';
    glow.style.top = e.pageY + 'px';
    document.body.appendChild(glow);
    
    setTimeout(() => {
        glow.remove();
    }, 1000);
});

// Add hover effect to timeline items
document.querySelectorAll('.timeline-item').forEach(item => {
    item.addEventListener('mouseenter', () => {
        item.style.transform = 'translateX(10px)';
    });
    
    item.addEventListener('mouseleave', () => {
        item.style.transform = 'translateX(0)';
    });
});

// Project Documents Data
const documents = {
    secarch: {
        title: 'Security Architecture Recommendations',
        content: `
            <h1>Security Architecture Recommendations</h1>
            
            <table>
                <thead>
                    <tr>
                        <th>Approach</th>
                        <th>Function / Focus</th>
                        <th>Strengths</th>
                        <th>Limitations</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><strong>Castle & Moat</strong></td>
                        <td>Builds a strong perimeter around the network like a castle wall. Once inside, users often have broad access.</td>
                        <td>Simple to understand, strong perimeter defences, firewalls, IDS, honeypots.</td>
                        <td>Outdated for remote/cloud use; weak against insider threats.</td>
                    </tr>
                    <tr>
                        <td><strong>Layered Security</strong></td>
                        <td>Stacks multiple protective tools, firewalls, antivirus, intrusion detection, backups.</td>
                        <td>Practical, reduces reliance on one tool, common in business environments.</td>
                        <td>Focused mainly on technology; doesn't cover people/policy; still vulnerable to insiders.</td>
                    </tr>
                    <tr>
                        <td><strong>Defence in Depth</strong></td>
                        <td>Military-inspired strategy: multiple layers of protection across technical, physical, and human levels.</td>
                        <td>Holistic — includes training, governance, monitoring, encryption, and controls.</td>
                        <td>Complex to manage, resource-intensive, may slow operations.</td>
                    </tr>
                    <tr>
                        <td><strong>Zero Trust</strong></td>
                        <td>"Never trust, always verify." Strict identity, access control, and continuous verification.</td>
                        <td>Strong for remote/cloud, stops lateral movement, aligns with government standards.</td>
                        <td>Implementation complexity: cultural/technical shift needed.</td>
                    </tr>
                </tbody>
            </table>
            
            <p>As the organization transitions to remote work and manages highly sensitive Department of Defence information, it is essential that the security framework remains robust and effective. Perimeter defences like Castle & Moat, are not sufficient anymore, and the company needs a strategy that can withstand advanced persistent threats, like those from nation state players.</p>
            
            <h2>Recommended Approaches</h2>
            
            <h3>1. Zero Trust Security</h3>
            <p>Zero Trust needs to be the primary of the security architecture for the organization. It follows the <strong>never trust, always verify</strong> principle. Even users or devices already in the network are not automatically trusted. For the organization, this will mean:</p>
            <ul>
                <li>Requiring multi-factor authentication from all employees, contractors, and partners.</li>
                <li>Continuing to monitor user and device activity for detecting anomalies.</li>
                <li>Applying least-privilege access, so employees only have access to what they need.</li>
                <li>Segregating DoD data, ensuring that it is stored isolated from less sensitive corporate networks.</li>
            </ul>
            <p>Zero Trust confronts the risks of remote work and insider threats directly, both of which are in cause when handling defence-related information.</p>
            
            <h3>2. Defence in Depth</h3>
            <p>Defence in Depth is required for Zero Trust. This involves building numerous layers of defence across the organization's surroundings, so that if one control is compromised, others remain to provide protection. Some of the principal elements include:</p>
            <ul>
                <li>Encryption of DoD data in transit and stored, using defence-approved methods.</li>
                <li>Segmentation of the network, with defence data isolated in high security zones.</li>
                <li>Improved monitoring and logging, with all access being traceable and auditable.</li>
                <li>Regular penetration testing and red teaming, simulating real attack scenarios.</li>
                <li>Employee insider-threat training and security awareness for staff handling sensitive data.</li>
            </ul>
            <p>This approach ensures that security is not relying on any point of failure but is embedded within the organization's people, processes, and technology.</p>
            
            <h3>3. Layered Security (Operational Controls)</h3>
            <p>While Defence in Depth is the overarching strategy, practical layered security measures remain essential day-to-day. The organization should continue to use firewalls, intrusion prevention systems, endpoint detection and response, patch management, and email filtering. These layers provide resilience against common attack vectors like phishing and ransomware.</p>
            
            <h2>Why a Mix of Controls</h2>
            <p>If the organization adopts a Zero Trust approach as the foundation, it will strengthen its security posture, but that does not remove the need for broader strategies. Zero Trust is a mindset built on never trusting and always verifying users, devices, and connections. It is especially effective at preventing insider threats and credential misuse, because even someone already inside the network still must prove their identity and justify their access.</p>
            
            <p>Defence in Depth sits on top of this, providing wider coverage through multiple layers of protection. So, if one measure fails, another takes over. This includes not just technical defences but also staff training, backup systems, monitoring, and physical safeguards.</p>
            
            <p>Alongside this, Layered Security offers practical day-to-day controls, such as firewalls, endpoint protection, and email filtering, which reduce the risk from common attack vectors. Together, this mix ensures the organization has both the modern precision of Zero Trust and the resilience of traditional layered defences.</p>
            
            <h2>Approaches Not Recommended</h2>
            <p><strong>Castle & Moat:</strong> Although once effective, this approach assumes that threats come only from outside and that everything inside the network can be trusted. With remote working and cloud services, this model is unsuitable for the organization's needs. Certain perimeter tools (such as honeypots and intrusion detection) may still be used as supporting controls but should not form the core strategy.</p>
            
            <h2>A Potential Scenario</h2>
            <p>The organization could design a multi-approach system by combining Zero Trust, Defence in Depth, and Layered Security. If one layer fails, the others catch the risk. For example, if an email filter misses a phishing attempt and an employee enters their login details, Zero Trust would prevent the attacker from gaining access by enforcing multi-factor authentication and monitoring behaviour. Without Zero Trust, the compromise could escalate, showing why multiple approaches are necessary.</p>
        `
    },
    appsec: {
        title: 'Application Security',
        content: `
            <h1>Application Security</h1>
            
            <h2>Introduction</h2>
            <p>This report provides remediation advice based off the findings identified during the penetration testing conducted by Hackmanit GmbH. The evaluation, completed in March 2019, identified 10 security weaknesses. This consisted of one high-severity vulnerability, six medium-severity vulnerabilities and two low-severity vulnerabilities.</p>
            
            <p>This report is aiming to achieve the following goals:</p>
            <ul>
                <li>Outline the vulnerability discovered during the security assessment of the DENIC ID system.</li>
                <li>Evaluate how each issue could impact the confidentiality, integrity and availability of the system and its users.</li>
                <li>Provide actionable remediations steps to address the identified weaknesses and reduce risk.</li>
                <li>Suggest long term strategies and security controls to prevent reoccurrence of similar vulnerabilities in future deployment.</li>
            </ul>
            
            <p>Implementing the remediations measures detailed in this report will enable DENIC ID to strengthen the overall security framework and maintain alignment with industry-recognised principles for federated identity systems and OpenID Connect protocols.</p>
            
            <h2>Cross-Site Request Forgery (CSRF)</h2>
            
            <h3>Vulnerabilities Identified</h3>
            <p>Cross Site Request Forgery is a type of attack where a victim's browser is tricked into making a hidden request to the hacked web application where the victim is already logged in. If the application does not validate the sender of the request, the hacker can trick the browser into doing unauthorized things on behalf of the user.</p>
            
            <p><strong>For example:</strong> A user is logged on to a bank website. Under this state, they navigate to a malicious site that instantly initiates money transfer request along with session cookies of the bank website.</p>
            
            <h3>Evaluation of Impact</h3>
            <p><strong>Security Threats:</strong> A hacker or a malicious actor can takeover of an account with an email or password change. They can execute malicious operations for instance, unauthorized fund transfer or posting information. In the consequence of this attack to organisation can leakage or corruption of data which wouldn't be the last or the least when it makes it possible for hackers to escalate their privilege.</p>
            
            <p><strong>Business Impacts:</strong> The organisation will face reputation damage and financial loss also there can be fines by the authorities for breaching the regulations. And eventually the org can face operational dysfunctions.</p>
            
            <h3>Actionable Remediation</h3>
            <p><strong>CSRF Tokens:</strong></p>
            <ul>
                <li>Generate a new token on each user session</li>
                <li>Add it in each form or changing request such as POST, PUT and DELETE</li>
                <li>Check the token on the server against the one stored in the session</li>
            </ul>
            
            <p><strong>SameSite Cookies:</strong> Set cookies with the [SameSite=Strict or SameSite=Lax] attribute, which prevents browsers from sending cookies on cross origin requests.</p>
            
            <p><strong>Double Submit Cookie Pattern:</strong></p>
            <ul>
                <li>Set a cookie containing a CSRF token</li>
                <li>Ask client to send that value as well in a custom HTTP header or a form</li>
                <li>Server check both values are the same</li>
            </ul>
            
            <p>Deploying the solution can be achieved by utilizing multiple platforms by doing some reconfiguration and a few lines of code. For example, we can use python to add CSRF token to our sessions and keep it safe from any exposure.</p>
            
            <h3>Long-term Strategies and Controls</h3>
            <ul>
                <li><strong>Turn On CSRF Protection by Default</strong> by making it required for all new web forms and backend API to use tokens</li>
                <li><strong>Security Testing</strong> by including CSRF testing in manual and automated pen tests we can make sure all these measures have been met</li>
                <li><strong>Developer Education:</strong> Not using insecure GET methods for sensitive actions, not depending on Referrer headers alone, understanding XSS vs CSRF</li>
                <li><strong>Strong Session Handling:</strong> Implement CSRF defence along with strong session management such as timeouts, HttpOnly and Secure cookies</li>
                <li><strong>Secure Configuration Reviews:</strong> Regularly review cookie settings such as SameSite, Secure, HTTPOnly and form protections</li>
            </ul>
            
            <h2>Unsigned JWTs Accepted</h2>
            
            <h3>Vulnerabilities Identified</h3>
            <p>A JWT is a small, independent token format used to safely move user identify information across systems. It usually includes:</p>
            <ul>
                <li>The header contains information on the token type and algorithm used (e.g., RS256)</li>
                <li>Payload information includes subject/user ID, issuer, and expiration time</li>
                <li>Signature is the cryptographic stamp that ensures the token has not been modified</li>
            </ul>
            
            <p>However, the system has been detected to accept unsigned JSON Web Tokens. They are intended to be signed with algorithms like HS256 or RS256, which ensures their integrity and validity. When unsigned JWTs (for example, those with the "alg": "none" header) are accepted by a server without verification, the identity agent has a vulnerability in which it accepts unsigned JSON Web Tokens (JWTs) or tokens with the alg: none algorithm without verification.</p>
            
            <h3>Evaluation of Impact</h3>
            <p><strong>Key points to be noted:</strong></p>
            <ul>
                <li>Attackers can access a user's information by knowing their subject identification</li>
                <li><strong>Sub claim:</strong> Sub stands for subject. The system assigns each user a unique identifier (similar to a user ID or email address)</li>
                <li><strong>ISS claim:</strong> ISS stands for issuer. It informs the system about who created the token</li>
            </ul>
            
            <table>
                <thead>
                    <tr>
                        <th>Class Type</th>
                        <th>Impact</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>Unauthorized access to user data or authentication bypass</td>
                        <td>Attackers can gain access to any user's personal information by creating a token with predetermined sub values</td>
                    </tr>
                    <tr>
                        <td>Privilege escalation</td>
                        <td>Attackers may mimic high-privilege users (such as administrators), resulting in data breaches, configuration modifications, or service disruptions</td>
                    </tr>
                    <tr>
                        <td>Data integrity violation</td>
                        <td>Accepting unsigned JWTs makes all data in JWT untrustworthy, which damages trust in the identity and access management system</td>
                    </tr>
                    <tr>
                        <td>Non compliant</td>
                        <td>This could lead to data protection violation and result in penalties</td>
                    </tr>
                    <tr>
                        <td>Data confidentiality loss</td>
                        <td>Sensitive or private user info being leaked</td>
                    </tr>
                </tbody>
            </table>
            
            <h3>Actionable Remediation</h3>
            <ul>
                <li><strong>Enforce validation of algorithm:</strong> Ensure the server rejects tokens with "alg": "none". Configure the JWT library to only support secure algorithms like RS256 or HS256</li>
                <li><strong>Use of existing JWT libraries:</strong> Avoid developing specialised JWT decoder or reader. Use clean libraries that verify signatures by default</li>
                <li><strong>Integrating signature validation:</strong> Verify the signature of each receiving JWT with a trusted secret or public key. Reject JWTs with unsigned tokens with an invalid or missing signature. Only accept tokens that are signed with secure algorithms like RS256 or HS256</li>
            </ul>
            
            <h3>Long-term Solutions and Controls</h3>
            <ul>
                <li><strong>Security and configuration audits:</strong> Regularly audit and test JWT configurations to verify that insecure options are not enabled</li>
                <li><strong>Training and development:</strong> Train engineering teams about secure token management and frequent authentication issues</li>
                <li><strong>Automated Security Testing:</strong> Integrate both dynamic and static evaluation tools into the CI/CD workflow</li>
                <li><strong>Security Policies:</strong> Maintain security regulations that prohibit the use of insecure JWT algorithms</li>
                <li><strong>Monitoring and Logging:</strong> Log and notify on invalid or unsigned JWTs. Use abnormality detection to identify repeated access attempts with fake tokens</li>
            </ul>
            
            <h2>Clickjacking Vulnerability</h2>
            
            <h3>Vulnerability Identified</h3>
            <p>Clickjacking is a deception attack, exploiting the trust between users and a legitimate application by embedding hidden or transparent frames within the application interface. Users are hijacked and redirected to perform unintended actions through manipulated visual presentations of the interface.</p>
            
            <p>The penetration test revealed that the DENIC ID's web interface is vulnerable to clickjacking attacks which falls under the medium-severity level. This issue has stemmed from the absence of security headers such as X-Frame-Options or a Content Security Policy on the web interface.</p>
            
            <h3>Evaluation of Impact</h3>
            <p>The impacts that were outlined within the report exposed the system to the risk of critical elements such as authentication or consent dialogs to be embedded with malicious sites through the use of iframes. From an organisational standpoint the broader consequences include:</p>
            <ul>
                <li>User Compromise</li>
                <li>Reputational Damage</li>
                <li>Data Privacy Violations</li>
                <li>Compliance Risks</li>
                <li>Technical Risk Amplification</li>
            </ul>
            
            <h3>Actionable Remediations</h3>
            <p>A solution recognised to mitigate the clickjacking vulnerability was to implement the X-Frame-Option HTTP Header, which is a browser-based security header. This restricts how and where the DENIC ID web pages can be embedded. Another solution suggested was the use of Content Security Policy which works well with X-Frame-Options.</p>
            
            <p>Additional countermeasures include:</p>
            <ul>
                <li><strong>UI Hardening Techniques:</strong> Frame-busting JavaScript and transparency detection support identifying suspicious behaviour in real-time</li>
                <li><strong>Visual Cues for User Confidence:</strong> Consistency in branding and recognisable domain names can reduce the rate of deception</li>
                <li><strong>Context-Aware Authorisation:</strong> Requiring extra steps such as re-authentication for explicit consent dialogues</li>
                <li><strong>Security Testing Integration:</strong> Automated tools such as OWASP ZAP or Burp Suite can be implemented</li>
            </ul>
            
            <h3>Long-term Strategies and Controls</h3>
            <ul>
                <li><strong>DNS-Based Protection (Advanced):</strong> Enabling CSP violation reporting can proactively detect potential attacks</li>
                <li><strong>Regular Testing:</strong> Conduction of regular penetration testing and monitoring of system security</li>
            </ul>
            
            <h2>Client Registration Endpoint</h2>
            
            <h3>Vulnerabilities Identified</h3>
            <p><strong>Finding:</strong> HTTP redirect URL allowed<br>
            <strong>Risk:</strong> Medium<br>
            <strong>Category:</strong> Authentication / Misconfiguration</p>
            
            <p><strong>Issue:</strong></p>
            <ul>
                <li>Localhost is correctly rejected</li>
                <li>However, https is not enforced for web clients</li>
            </ul>
            
            <p><strong>Security Risk:</strong></p>
            <ul>
                <li><strong>Potential MITM attack:</strong> During auth redirection for web clients using http</li>
                <li><strong>Token Leak:</strong> Without encryption access tokens in the URL could be exposed to eavesdropping</li>
                <li><strong>Session Hijacking:</strong> Attacker could redirect the user to a malicious site impersonating a legitimate URL</li>
                <li><strong>Phishing:</strong> Users may unknowingly be redirected to deceptive and insecure URLs</li>
            </ul>
            
            <h3>Evaluation of Impact</h3>
            <ul>
                <li>Potential for compromised accounts</li>
                <li>Massive reputational damage</li>
                <li>Compliance violations (GDPR)</li>
                <li>Loss of company trust</li>
            </ul>
            
            <h3>Actionable Remediations</h3>
            <ul>
                <li>Enforce https-only redirect URLs for all web application registrations</li>
                <li>Validate URL scheme and issue clear error message when http is used</li>
                <li>Ensure the authorisation server strictly validates redirect URLs against a predefined list of exact matches</li>
            </ul>
            
            <h2>Brute Force and Denial of Service</h2>
            
            <h3>Vulnerabilities Identified</h3>
            <p>Two of the most common threats can severely impact system security and availability. They are known as Brute-force and Denial of Service (DoS) attacks. An attack that involves repeatedly guessing login credentials and using automated tools until access is gained. A DoS attack has a slightly different approach by excessively requesting and overwhelming the system.</p>
            
            <p>The penetration test exposed that the organisation had weak protection against brute-force and DoS attacks. This depicts that there wasn't adequate controls in place to limit and mitigate repeated login attempts.</p>
            
            <h3>Evaluation of Impact</h3>
            <ul>
                <li>User accounts could be compromised, especially users reusing simple or common passwords</li>
                <li>Services might go offline or slow down due to high volumes of traffic from the attack</li>
                <li>Dealing with a high volume of complaints, system alerts and password resets will cause major stress for the Support team</li>
                <li>Loss of integrity - poor system performance could cause customers to lose confidence</li>
            </ul>
            
            <h3>Actionable Remediation</h3>
            <ul>
                <li><strong>Rate limiting:</strong> Login attempts per user, or IP limited to a certain amount (for example, 5 attempts per minute)</li>
                <li><strong>CAPTCHA:</strong> After a few failed attempts adding a CAPTCHA can mitigate bots endlessly trying to guess passwords</li>
                <li><strong>Temporary lockouts:</strong> The succession of back-to-back failed attempts will lock the account for a short time and alert admins</li>
                <li><strong>Login activity:</strong> By monitoring this type of activity for any sudden spike in failed attempts or unusual log alerts</li>
            </ul>
            
            <h3>Long-term Solutions and Controls</h3>
            <p>To prevent such events repeating themselves in future, building security development from the start is critical. The use of threat modelling would be critical in helping map out what could go wrong and plan for it. Even the use of testing authentication systems regularly could be a part of the software development cycle.</p>
            
            <p>Taking these factors into consideration, simply reviewing and improving the defenses is essential. This is because, as the attacks evolve, so should your defenses. To conclude, encourage users to take advantage of multifactor authentication and simply strong passwords wherever possible.</p>
            
            <h2>Conclusion</h2>
            <p>The security evaluation conducted on the DENIC ID platform uncovered several vulnerabilities affecting core components of the identity flow and user session management. These included weaknesses such as unverified JWT signatures, exposure to clickjacking, insufficient CSRF protections, improper redirect URI handling, and lack of brute-force resistance.</p>
            
            <p>This report outlines both immediate and strategic remediation steps for each identified issue. Technical recommendations include enforcing strict header policies (like CSP and X-Frame-Options), improving session binding, implementing token misuse detection, and strengthening client-side and server-side validation.</p>
            
            <p>Long-term application security depends on continuous investment in secure coding practices, threat modeling, and validation. By embedding these principles into development and operational workflows, DENIC ID can maintain a robust defense posture, protect identity data, and ensure compliance with best practices in OpenID Connect and federated identity protocols.</p>
        `
    },
    pam: {
        title: 'Understanding Privileged Access Management (PAM)',
        content: `
            <h1>Understanding Privileged Access Management (PAM)</h1>
            
            <p>In today's digital environment, cyber attackers are continually seeking ways to gain control of high-value systems. One of the most common attack routes is through privileged accounts. These are administrator, root, or service accounts that have elevated permissions within IT environments. If these accounts are compromised, attackers can move laterally through systems, disable defences, steal data, or disrupt critical operations.</p>
            
            <p>This is where Privileged Access Management (PAM) becomes essential. PAM is a key area of cybersecurity that is designed to secure, control, and monitor privileged accounts and access within an organisation. It helps to reduce risk by enforcing the principle of least privilege and preventing misuse of elevated credentials.</p>
            
            <h2>What is Privileged Access Management?</h2>
            
            <p>Privileged Access Management (PAM) refers to a structured set of tools, policies, and practices used to protect privileged accounts and the access they provide. These accounts have extensive powers that can affect system configurations, user permissions, and data access.</p>
            
            <p>Privileged accounts may include:</p>
            <ul>
                <li>System administrators with control over operating systems or databases</li>
                <li>Network engineers managing routers, switches, and firewalls</li>
                <li>Service accounts used by applications to communicate with databases or systems</li>
                <li>Root or domain administrator accounts that control entire infrastructures</li>
            </ul>
            
            <p>Because these accounts can override security controls, they must be strictly managed and monitored. PAM ensures that only authorised personnel can access these accounts, and only under controlled conditions.</p>
            
            <h2>How PAM Works: Core Components and Process</h2>
            
            <p>PAM solutions combine several technical and procedural controls to protect privileged access. The main components are as follows:</p>
            
            <h3>Credential Vaulting</h3>
            <p>Privileged passwords, SSH keys, and API tokens are stored in an encrypted vault. Users do not see or handle the actual password. The PAM tool retrieves and uses it automatically when needed. This prevents password sharing, reuse, and theft.</p>
            <ul>
                <li>When an administrator or application needs to perform a privileged action, they request access through the PAM system.</li>
                <li>The PAM system authenticates the requester (e.g., via SSO, MFA, or LDAP).</li>
                <li>The vault then retrieves and injects the credential into the target system/session, without exposing it to the user.</li>
            </ul>
            
            <h3>Session Brokering and Monitoring</h3>
            <p>When a privileged session is started, the PAM system connects the user to the target system without revealing credentials. The session may be:</p>
            <ul>
                <li>Recorded for audit and compliance purposes</li>
                <li>Monitored in real time by security teams</li>
                <li>Terminated automatically if suspicious behaviour is detected</li>
            </ul>
            
            <h3>Just-in-Time (JIT) Access</h3>
            <p>Users are granted privileged access only for a specific task or a defined period. Once the task is complete, access is automatically revoked. This minimises the risk window for attacks.</p>
            
            <h3>Least Privilege Enforcement</h3>
            <p>Every user is given only the permissions necessary to perform their job. For example, a technician may restart a server but not alter its configuration.</p>
            
            <h3>Auditing and Reporting</h3>
            <p>All privileged activities, including logins, commands, and system changes, are logged and auditable. This enables:</p>
            <ul>
                <li>Compliance with standards such as ISO 27001, NIST, and PCI DSS</li>
                <li>Investigation and forensic analysis after incidents</li>
                <li>Continuous monitoring for unusual activity</li>
            </ul>
            
            <h3>Automated Password Rotation</h3>
            <p>PAM systems can automatically change and randomise passwords after each use, ensuring that no credential remains static or is reused.</p>
            
            <h2>PAM Workflow Example</h2>
            <ol>
                <li>A system administrator requests elevated access through the PAM portal.</li>
                <li>The request is reviewed and approved by a manager or automatically according to policy.</li>
                <li>The PAM tool connects to the target system on behalf of the user.</li>
                <li>The session is recorded and monitored in real time.</li>
                <li>Once the task is complete, privileges are revoked and passwords are rotated.</li>
            </ol>
            
            <h2>PAM and Identity Access Management (IAM)</h2>
            
            <p>Although PAM and IAM both deal with access control, they focus on different users and permissions.</p>
            
            <table>
                <thead>
                    <tr>
                        <th>Aspect</th>
                        <th>Identity and Access Management (IAM)</th>
                        <th>Privileged Access Management (PAM)</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><strong>Primary Focus</strong></td>
                        <td>Manages all user identities (employees, customers, partners)</td>
                        <td>Manages privileged or administrative accounts</td>
                    </tr>
                    <tr>
                        <td><strong>Access Level</strong></td>
                        <td>Regular user access</td>
                        <td>Elevated or administrative access</td>
                    </tr>
                    <tr>
                        <td><strong>Purpose</strong></td>
                        <td>Ensures users can log in and access necessary resources</td>
                        <td>Protects and monitors high-risk accounts</td>
                    </tr>
                    <tr>
                        <td><strong>Key Functions</strong></td>
                        <td>Authentication, authorisation, single sign-on, multi-factor authentication</td>
                        <td>Credential vaulting, session monitoring, least privilege enforcement</td>
                    </tr>
                    <tr>
                        <td><strong>Example Tools</strong></td>
                        <td>Okta, Azure AD, Ping Identity</td>
                        <td>CyberArk, BeyondTrust, Delinea, One Identity</td>
                    </tr>
                    <tr>
                        <td><strong>Security Goal</strong></td>
                        <td>Manage and verify identity</td>
                        <td>Control and monitor powerful access</td>
                    </tr>
                </tbody>
            </table>
            
            <p>In simple terms: IAM manages who you are and whether you can access systems. PAM controls what you can do once you have that access, particularly if you have high-level privileges.</p>
            
            <h2>Why PAM Matters</h2>
            
            <p>Without PAM, privileged credentials can become a major vulnerability. Research indicates that approximately 80 per cent of security breaches involve the misuse or compromise of privileged accounts. Implementing PAM can significantly reduce attack surfaces, especially when combined with least-privilege principles.</p>
            
            <p>PAM also assists organisations in meeting compliance requirements under security frameworks such as:</p>
            <ul>
                <li>ISO/IEC 27001</li>
                <li>NIST 800-53</li>
                <li>PCI DSS</li>
                <li>Sarbanes-Oxley (SOX)</li>
            </ul>
            
            <h2>Best Practices for Implementing PAM</h2>
            <ol>
                <li>Identify all privileged accounts, including hidden or embedded ones.</li>
                <li>Apply the principle of least privilege across the organisation.</li>
                <li>Automate password management and eliminate shared credentials.</li>
                <li>Implement multi-factor authentication for all administrative access.</li>
                <li>Continuously monitor and audit privileged sessions.</li>
                <li>Review PAM policies regularly to adapt to emerging threats.</li>
            </ol>
            
            <h2>References</h2>
            <ol>
                <li>CyberArk. What Is Privileged Access Management (PAM)? <a href="https://www.cyberark.com/what-is/pam/" target="_blank">https://www.cyberark.com/what-is/pam/</a></li>
                <li>Gartner Research. Market Guide for Privileged Access Management.</li>
                <li>BeyondTrust. Privileged Access Management Explained.</li>
                <li>NIST Special Publication 800-53. Security and Privacy Controls for Federal Information Systems.</li>
                <li>Microsoft Learn. Privileged Identity Management Overview.</li>
            </ol>
        `
    }
};

// Modal functionality
const modal = document.getElementById('documentModal');
const modalTitle = document.getElementById('modalTitle');
const modalBody = document.getElementById('modalBody');
const modalClose = document.querySelector('.modal-close');

// Open modal when file is clicked
document.querySelectorAll('.file-item').forEach(item => {
    item.addEventListener('click', () => {
        const fileKey = item.getAttribute('data-file');
        const doc = documents[fileKey];
        
        if (doc) {
            modalTitle.textContent = doc.title;
            modalBody.innerHTML = doc.content;
            modal.classList.add('active');
            document.body.style.overflow = 'hidden';
        }
    });
});

// Close modal
modalClose.addEventListener('click', () => {
    modal.classList.remove('active');
    document.body.style.overflow = 'auto';
});

// Close modal when clicking outside
modal.addEventListener('click', (e) => {
    if (e.target === modal) {
        modal.classList.remove('active');
        document.body.style.overflow = 'auto';
    }
});

// Close modal with Escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && modal.classList.contains('active')) {
        modal.classList.remove('active');
        document.body.style.overflow = 'auto';
    }
});
