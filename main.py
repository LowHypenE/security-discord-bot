import discord
import re
import aiohttp
import tldextract
from bs4 import BeautifulSoup
from discord import app_commands
from discord.ext import commands

# ====== CONFIG ======
TOKEN = "MTM4MjEyMDAxMDg3MjUyNDg3MA.GEaaH2.haCAcOlpMY_di0_TqcdtovHbmKX6VHx8_mvCBc"
MOD_ROLE_IDS = [1382126802352214026]  # Replace with actual role IDs

BANNED_DOMAINS = set([
    "grabify.link", "iplogger.org", "2no.co", "gyazo.in", "yip.su",
    "ipgraber.ru", "blasze.com", "stopify.co", "bmwforum.co"
])

WHITELISTED_DOMAINS = set()
TRUSTED_USERS = set()
CUSTOM_PREFIX = "!"
ALERT_CHANNEL_ID = None

SUSPICIOUS_KEYWORDS = [
    "free nitro", "discord nitro", "steam gift", "airdrop",
    "verify your account", "claim reward", "click this", "gift dropped"
]

# ====== SETUP ======
intents = discord.Intents.default()
intents.message_content = True
intents.messages = True
intents.guilds = True
intents.members = True

bot = commands.Bot(command_prefix=lambda bot, msg: CUSTOM_PREFIX, intents=intents)
tree = bot.tree

url_regex = re.compile(r'https?://[^\s]+')

async def fetch_url_content(url):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=5, allow_redirects=True) as response:
                return await response.text()
    except:
        return ""

def extract_text_from_html(html):
    soup = BeautifulSoup(html, "html.parser")
    return soup.get_text().lower()

def get_domain_from_url(url):
    extracted = tldextract.extract(url)
    return f"{extracted.domain}.{extracted.suffix}"

async def scan_url(url, message_text=""):
    issues = []
    domain = get_domain_from_url(url)

    if domain in WHITELISTED_DOMAINS:
        return []

    if domain in BANNED_DOMAINS:
        issues.append(f"🚨 Malicious domain: `{domain}`")

    html = await fetch_url_content(url)
    if html:
        text = extract_text_from_html(html)
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in text or keyword in message_text.lower():
                issues.append(f"⚠️ Suspicious keyword: `{keyword}`")

    return issues

async def scan_message(message):
    if message.author.id in TRUSTED_USERS:
        return []
    urls = url_regex.findall(message.content)
    found_issues = []
    for url in urls:
        issues = await scan_url(url, message.content)
        found_issues.extend(issues)
    return found_issues

async def send_security_alert(ctx, message, issues):
    embed = discord.Embed(title="⚠️ Potential Threat Detected", color=0xff3333)
    embed.add_field(name="User", value=message.author.mention, inline=True)
    embed.add_field(name="Channel", value=message.channel.mention, inline=True)
    embed.add_field(name="Content", value=message.content[:1000], inline=False)
    embed.add_field(name="Detected Issues", value="\n".join(issues), inline=False)
    embed.set_footer(text=f"Message ID: {message.id} | User ID: {message.author.id}")

    view = discord.ui.View()

    async def forget_callback(interaction):
        await interaction.response.send_message("✅ Issue forgotten.", ephemeral=True)
        view.disable_all_items()

    async def mute_callback(interaction):
        if message.guild:
            muted_role = discord.utils.get(message.guild.roles, name="Muted")
            if not muted_role:
                muted_role = await message.guild.create_role(name="Muted")
                for channel in message.guild.channels:
                    await channel.set_permissions(muted_role, send_messages=False, speak=False)
            await message.author.add_roles(muted_role)
            await interaction.response.send_message(f"🔇 {message.author.mention} has been muted.", ephemeral=True)
            view.disable_all_items()

    async def investigate_callback(interaction):
        await interaction.response.send_message("🔎 Investigation started.", ephemeral=True)
        view.disable_all_items()

    view.add_item(discord.ui.Button(label="Forget", style=discord.ButtonStyle.secondary, custom_id="forget"))
    view.add_item(discord.ui.Button(label="Mute Member", style=discord.ButtonStyle.danger, custom_id="mute"))
    view.add_item(discord.ui.Button(label="Investigate", style=discord.ButtonStyle.primary, custom_id="investigate"))

    async def interaction_check(interaction):
        role_ids = [role.id for role in interaction.user.roles]
        if interaction.user.id == message.guild.owner_id or any(rid in MOD_ROLE_IDS for rid in role_ids):
            return True
        await interaction.response.send_message("❌ You don't have permission.", ephemeral=True)
        return False

    view.interaction_check = interaction_check
    view.children[0].callback = forget_callback
    view.children[1].callback = mute_callback
    view.children[2].callback = investigate_callback

    try:
        if ALERT_CHANNEL_ID:
            alert_channel = bot.get_channel(ALERT_CHANNEL_ID)
            await alert_channel.send(embed=embed, view=view)
        else:
            await ctx.send(embed=embed, view=view)
    except:
        pass

@bot.event
async def on_ready():
    await tree.sync()
    print(f"[+] Logged in as {bot.user}")

@bot.event
async def on_message(message):
    if message.author.bot:
        return
    issues = await scan_message(message)
    if issues:
        await send_security_alert(message.channel, message, issues)
    await bot.process_commands(message)

@tree.command(name="scanme", description="Scan your most recent message")
async def scanme(interaction: discord.Interaction):
    await interaction.response.defer()
    async for msg in interaction.channel.history(limit=20):
        if msg.author == interaction.user:
            issues = await scan_message(msg)
            if issues:
                await send_security_alert(interaction.channel, msg, issues)
                await interaction.followup.send("⚠️ Your message was flagged.")
            else:
                await interaction.followup.send("✅ No issues found.")
            return
    await interaction.followup.send("No recent messages found.")

@tree.command(name="scanall", description="Scan recent messages in this channel")
@app_commands.describe(limit="Number of messages to scan")
async def scanall(interaction: discord.Interaction, limit: int = 25):
    await interaction.response.defer()
    count = 0
    async for msg in interaction.channel.history(limit=limit):
        issues = await scan_message(msg)
        if issues:
            await send_security_alert(interaction.channel, msg, issues)
            count += 1
    await interaction.followup.send(f"✅ Scan complete. {count} threats found.")

@tree.command(name="whitelist", description="Add a domain to the whitelist")
async def whitelist(interaction: discord.Interaction, domain: str):
    WHITELISTED_DOMAINS.add(domain)
    await interaction.response.send_message(f"✅ `{domain}` added to whitelist.")

@tree.command(name="blacklist", description="Add a domain to the blacklist")
async def blacklist(interaction: discord.Interaction, domain: str):
    BANNED_DOMAINS.add(domain)
    await interaction.response.send_message(f"🚫 `{domain}` added to blacklist.")

@tree.command(name="trust", description="Mark a user as trusted")
async def trust(interaction: discord.Interaction, user: discord.User):
    TRUSTED_USERS.add(user.id)
    await interaction.response.send_message(f"✅ {user.mention} marked as trusted.")

@tree.command(name="untrust", description="Remove a user from trusted list")
async def untrust(interaction: discord.Interaction, user: discord.User):
    TRUSTED_USERS.discard(user.id)
    await interaction.response.send_message(f"❌ {user.mention} removed from trusted list.")

@tree.command(name="prefix", description="Change the bot's prefix")
async def prefix(interaction: discord.Interaction, new_prefix: str):
    global CUSTOM_PREFIX
    CUSTOM_PREFIX = new_prefix
    await interaction.response.send_message(f"✅ Prefix changed to `{new_prefix}`")

@tree.command(name="setalertchannel", description="Set the alert channel")
async def setalertchannel(interaction: discord.Interaction):
    global ALERT_CHANNEL_ID
    ALERT_CHANNEL_ID = interaction.channel.id
    await interaction.response.send_message(f"✅ Alert channel set to {interaction.channel.mention}")

@tree.command(name="commands", description="List all commands")
async def commands_cmd(interaction: discord.Interaction):
    cmds = [
        "/scanme - Scan your most recent message",
        "/scanall <limit> - Scan messages in this channel",
        "/whitelist <domain> - Whitelist a domain",
        "/blacklist <domain> - Blacklist a domain",
        "/trust <user> - Mark a user as trusted",
        "/untrust <user> - Remove a trusted user",
        "/prefix <prefix> - Change command prefix",
        "/setalertchannel - Set the alert channel",
        "/commands - Show this command list"
    ]
    await interaction.response.send_message("\n".join(cmds) + "\n\nWanna request commands? Talk to @!Biscuit")

bot.run(TOKEN)
