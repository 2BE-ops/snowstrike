/**
 * SnowStrike Agent Avatars — 32-bit pixel-art anthropomorphized characters
 *
 * Each agent has a unique character rendered as inline SVG pixel art.
 * Characters animate based on agent state: thinking, writing, waiting, sleeping.
 */
const HexAvatars = (() => {
    const AGENT_ALIASES = {
        'BinaryRE Agent': 'Binary RE Agent',
    };

    function canonicalAgentName(agentName) {
        return AGENT_ALIASES[agentName] || agentName;
    }

    // ── Pixel grid helper ──────────────────────────────────────────
    // Draws an 16x16 pixel grid scaled up. Each "pixel" is a colored rect.
    function pixelGrid(pixels, scale = 3) {
        const size = scale;
        let rects = '';
        for (const [x, y, color] of pixels) {
            rects += `<rect x="${x * size}" y="${y * size}" width="${size}" height="${size}" fill="${color}"/>`;
        }
        const w = 16 * size, h = 16 * size;
        return `<svg viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" class="avatar-sprite">${rects}</svg>`;
    }

    // ── Character pixel maps ───────────────────────────────────────
    // 16x16 pixel art for each agent character

    const SKIN = '#FFDAB9';
    const SKIN_DARK = '#E8C4A0';
    const BLACK = '#1A1A1A';
    const WHITE = '#FFFFFF';
    const GRAY = '#888888';

    const CHARACTERS = {
        // Scout with hood & binoculars
        'Recon Agent': {
            body: (c) => {
                const HOOD = '#2E8B57';
                const HOOD_D = '#1E6B3A';
                const BINOC = '#444';
                return [
                    // Hood
                    [6,1,HOOD],[7,1,HOOD],[8,1,HOOD],[9,1,HOOD],
                    [5,2,HOOD],[6,2,HOOD_D],[7,2,HOOD_D],[8,2,HOOD_D],[9,2,HOOD_D],[10,2,HOOD],
                    [5,3,HOOD],[6,3,HOOD],[7,3,HOOD],[8,3,HOOD],[9,3,HOOD],[10,3,HOOD],
                    // Face
                    [6,4,SKIN],[7,4,SKIN],[8,4,SKIN],[9,4,SKIN],
                    [5,5,SKIN],[6,5,BLACK],[7,5,SKIN],[8,5,SKIN],[9,5,BLACK],[10,5,SKIN],
                    [6,6,SKIN],[7,6,SKIN],[8,6,SKIN_DARK],[9,6,SKIN],
                    // Binoculars (held up)
                    [3,4,BINOC],[4,4,BINOC],[11,4,BINOC],[12,4,BINOC],
                    [3,5,BINOC],[4,5,GRAY],[11,5,GRAY],[12,5,BINOC],
                    // Body (tunic)
                    [6,7,HOOD],[7,7,HOOD],[8,7,HOOD],[9,7,HOOD],
                    [5,8,HOOD],[6,8,HOOD_D],[7,8,HOOD_D],[8,8,HOOD_D],[9,8,HOOD_D],[10,8,HOOD],
                    [5,9,HOOD],[6,9,HOOD],[7,9,HOOD],[8,9,HOOD],[9,9,HOOD],[10,9,HOOD],
                    [5,10,HOOD],[6,10,HOOD],[7,10,HOOD],[8,10,HOOD],[9,10,HOOD],[10,10,HOOD],
                    // Arms
                    [4,7,SKIN],[4,8,SKIN],[11,7,SKIN],[11,8,SKIN],
                    // Belt
                    [6,11,'#8B6914'],[7,11,'#8B6914'],[8,11,'#8B6914'],[9,11,'#8B6914'],
                    // Legs
                    [6,12,HOOD_D],[7,12,HOOD_D],[8,12,HOOD_D],[9,12,HOOD_D],
                    [6,13,HOOD_D],[7,13,HOOD_D],[8,13,HOOD_D],[9,13,HOOD_D],
                    // Boots
                    [5,14,'#5C3317'],[6,14,'#5C3317'],[9,14,'#5C3317'],[10,14,'#5C3317'],
                    [5,15,'#5C3317'],[6,15,'#5C3317'],[9,15,'#5C3317'],[10,15,'#5C3317'],
                ];
            },
            accent: '#2E8B57',
        },

        // Spider on web
        'WebApp Agent': {
            body: () => {
                const BLUE = '#4A7FC4';
                const BLUE_D = '#3A6AA0';
                const WEB = '#CCCCCC';
                return [
                    // Web threads (background)
                    [0,0,WEB],[4,0,WEB],[8,0,WEB],[12,0,WEB],[15,0,WEB],
                    [1,1,WEB],[7,1,WEB],[13,1,WEB],
                    [2,2,WEB],[6,2,WEB],[10,2,WEB],[14,2,WEB],
                    [3,3,WEB],[5,5,WEB],[11,5,WEB],
                    // Spider body
                    [7,4,BLUE],[8,4,BLUE],
                    [6,5,BLUE],[7,5,BLUE_D],[8,5,BLUE_D],[9,5,BLUE],
                    [6,6,BLUE],[7,6,WHITE],[8,6,WHITE],[9,6,BLUE],
                    [6,7,BLUE],[7,7,BLACK],[8,7,BLACK],[9,7,BLUE],
                    [7,8,BLUE],[8,8,BLUE],
                    [6,9,BLUE_D],[7,9,BLUE],[8,9,BLUE],[9,9,BLUE_D],
                    [7,10,BLUE_D],[8,10,BLUE_D],
                    // Legs (8 legs, 4 each side)
                    [4,5,BLUE_D],[3,4,BLUE_D],[11,5,BLUE_D],[12,4,BLUE_D],
                    [4,7,BLUE_D],[3,8,BLUE_D],[11,7,BLUE_D],[12,8,BLUE_D],
                    [5,6,BLUE_D],[4,6,BLUE_D],[10,6,BLUE_D],[11,6,BLUE_D],
                    [5,8,BLUE_D],[4,9,BLUE_D],[10,8,BLUE_D],[11,9,BLUE_D],
                    // More web
                    [2,12,WEB],[5,11,WEB],[10,11,WEB],[13,12,WEB],
                    [1,13,WEB],[7,13,WEB],[8,13,WEB],[14,13,WEB],
                    [0,15,WEB],[4,14,WEB],[11,14,WEB],[15,15,WEB],
                ];
            },
            accent: '#4A7FC4',
        },

        // Knight with sword
        'Attack Agent': {
            body: () => {
                const RED = '#C44A4A';
                const RED_D = '#993333';
                const STEEL = '#B0B0B0';
                const STEEL_D = '#888888';
                return [
                    // Helmet
                    [6,0,STEEL],[7,0,STEEL],[8,0,STEEL],[9,0,STEEL],
                    [5,1,STEEL],[6,1,STEEL_D],[7,1,STEEL_D],[8,1,STEEL_D],[9,1,STEEL_D],[10,1,STEEL],
                    [5,2,STEEL],[6,2,STEEL],[7,2,STEEL],[8,2,STEEL],[9,2,STEEL],[10,2,STEEL],
                    // Visor
                    [6,3,BLACK],[7,3,STEEL],[8,3,STEEL],[9,3,BLACK],
                    [5,3,STEEL],[10,3,STEEL],
                    [6,4,SKIN],[7,4,SKIN],[8,4,SKIN],[9,4,SKIN],
                    // Plume
                    [10,0,RED],[11,0,RED],[11,1,RED],
                    // Body (armor)
                    [6,5,RED],[7,5,RED],[8,5,RED],[9,5,RED],
                    [5,6,RED],[6,6,RED_D],[7,6,STEEL],[8,6,STEEL],[9,6,RED_D],[10,6,RED],
                    [5,7,RED],[6,7,RED],[7,7,RED_D],[8,7,RED_D],[9,7,RED],[10,7,RED],
                    [5,8,RED],[6,8,RED],[7,8,RED],[8,8,RED],[9,8,RED],[10,8,RED],
                    [6,9,RED_D],[7,9,RED_D],[8,9,RED_D],[9,9,RED_D],
                    // Arms
                    [4,6,STEEL],[4,7,STEEL],[11,6,STEEL],[11,7,STEEL],
                    // Sword (right hand)
                    [12,5,STEEL],[12,4,STEEL],[12,3,STEEL],[12,2,STEEL],[12,1,'#FFD700'],
                    [11,5,'#8B6914'],[13,5,'#8B6914'],
                    // Shield (left hand)
                    [2,6,RED],[3,6,RED],[2,7,RED_D],[3,7,RED_D],[2,8,RED],[3,8,RED],
                    // Legs
                    [6,10,STEEL],[7,10,STEEL],[8,10,STEEL],[9,10,STEEL],
                    [6,11,RED_D],[7,11,RED_D],[8,11,RED_D],[9,11,RED_D],
                    [6,12,STEEL],[7,12,STEEL],[8,12,STEEL],[9,12,STEEL],
                    // Boots
                    [5,13,'#5C3317'],[6,13,'#5C3317'],[9,13,'#5C3317'],[10,13,'#5C3317'],
                    [5,14,'#5C3317'],[6,14,'#5C3317'],[9,14,'#5C3317'],[10,14,'#5C3317'],
                ];
            },
            accent: '#C44A4A',
        },

        // Wizard on cloud
        'Cloud Agent': {
            body: () => {
                const PURP = '#7E57C2';
                const PURP_D = '#5E3FA2';
                const CLOUD = '#E8E8E8';
                const CLOUD_D = '#D0D0D0';
                const STAR = '#FFD700';
                return [
                    // Hat point
                    [8,0,PURP],
                    [7,1,PURP],[8,1,PURP_D],[9,1,PURP],
                    [6,2,PURP],[7,2,PURP],[8,2,STAR],[9,2,PURP],[10,2,PURP],
                    // Hat brim
                    [4,3,PURP],[5,3,PURP],[6,3,PURP],[7,3,PURP],[8,3,PURP],[9,3,PURP],[10,3,PURP],[11,3,PURP],
                    // Face
                    [6,4,SKIN],[7,4,SKIN],[8,4,SKIN],[9,4,SKIN],
                    [6,5,BLACK],[7,5,SKIN],[8,5,SKIN],[9,5,BLACK],
                    [7,6,SKIN],[8,6,SKIN],
                    // Beard
                    [6,6,WHITE],[9,6,WHITE],
                    [6,7,WHITE],[7,7,WHITE],[8,7,WHITE],[9,7,WHITE],
                    // Robe
                    [5,8,PURP],[6,8,PURP],[7,8,PURP_D],[8,8,PURP_D],[9,8,PURP],[10,8,PURP],
                    [5,9,PURP],[6,9,PURP],[7,9,STAR],[8,9,PURP],[9,9,PURP],[10,9,PURP],
                    [4,10,PURP],[5,10,PURP],[6,10,PURP],[7,10,PURP],[8,10,PURP],[9,10,PURP],[10,10,PURP],[11,10,PURP],
                    // Staff (left hand)
                    [3,5,'#8B6914'],[3,6,'#8B6914'],[3,7,'#8B6914'],[3,8,'#8B6914'],[3,9,'#8B6914'],[3,10,'#8B6914'],
                    [3,4,STAR],[2,4,STAR],[4,4,STAR],[3,3,STAR],
                    // Cloud beneath
                    [3,12,CLOUD],[4,12,CLOUD],[5,12,CLOUD],[6,12,CLOUD],[7,12,CLOUD],[8,12,CLOUD],[9,12,CLOUD],[10,12,CLOUD],[11,12,CLOUD],[12,12,CLOUD],
                    [2,13,CLOUD_D],[3,13,CLOUD],[4,13,CLOUD],[5,13,CLOUD],[6,13,CLOUD],[7,13,CLOUD],[8,13,CLOUD],[9,13,CLOUD],[10,13,CLOUD],[11,13,CLOUD],[12,13,CLOUD],[13,13,CLOUD_D],
                    [4,14,CLOUD_D],[5,14,CLOUD_D],[10,14,CLOUD_D],[11,14,CLOUD_D],
                ];
            },
            accent: '#7E57C2',
        },

        // Tinkerer with goggles & wrench
        'BinaryRE Agent': {
            body: () => {
                const AMB = '#A67C2E';
                const AMB_D = '#866420';
                const GOGGLE = '#FFD700';
                const GOGGLE_D = '#CC9900';
                return [
                    // Hair / head
                    [6,1,AMB_D],[7,1,AMB_D],[8,1,AMB_D],[9,1,AMB_D],
                    [5,2,AMB_D],[6,2,SKIN],[7,2,SKIN],[8,2,SKIN],[9,2,SKIN],[10,2,AMB_D],
                    // Goggles
                    [4,3,GOGGLE_D],[5,3,GOGGLE],[6,3,GOGGLE],[7,3,SKIN],[8,3,SKIN],[9,3,GOGGLE],[10,3,GOGGLE],[11,3,GOGGLE_D],
                    [5,4,GOGGLE],[6,4,BLACK],[7,4,SKIN],[8,4,SKIN],[9,4,BLACK],[10,4,GOGGLE],
                    // Mouth
                    [7,5,SKIN],[8,5,SKIN_DARK],
                    // Body (overalls)
                    [6,6,AMB],[7,6,AMB],[8,6,AMB],[9,6,AMB],
                    [5,7,AMB],[6,7,AMB_D],[7,7,AMB_D],[8,7,AMB_D],[9,7,AMB_D],[10,7,AMB],
                    [5,8,AMB],[6,8,AMB],[7,8,AMB],[8,8,AMB],[9,8,AMB],[10,8,AMB],
                    [5,9,AMB],[6,9,AMB],[7,9,AMB],[8,9,AMB],[9,9,AMB],[10,9,AMB],
                    // Pocket
                    [8,8,GOGGLE_D],[9,8,GOGGLE_D],
                    // Arms
                    [4,7,SKIN],[4,8,SKIN],[11,7,SKIN],[11,8,SKIN],
                    // Wrench (right hand)
                    [12,6,GRAY],[12,7,GRAY],[13,6,GRAY],[13,5,GRAY],[14,5,GRAY],
                    [12,8,GRAY],
                    // Belt
                    [6,10,'#5C3317'],[7,10,'#5C3317'],[8,10,'#5C3317'],[9,10,'#5C3317'],
                    // Legs
                    [6,11,AMB_D],[7,11,AMB_D],[8,11,AMB_D],[9,11,AMB_D],
                    [6,12,AMB_D],[7,12,AMB_D],[8,12,AMB_D],[9,12,AMB_D],
                    // Boots
                    [5,13,'#5C3317'],[6,13,'#5C3317'],[9,13,'#5C3317'],[10,13,'#5C3317'],
                    [5,14,'#5C3317'],[6,14,'#5C3317'],[9,14,'#5C3317'],[10,14,'#5C3317'],
                ];
            },
            accent: '#A67C2E',
        },

        // Detective with magnifying glass
        'OSINT Agent': {
            body: () => {
                const BLUE = '#4A90C4';
                const BLUE_D = '#3670A0';
                const HAT = '#2C3E50';
                return [
                    // Fedora
                    [5,0,HAT],[6,0,HAT],[7,0,HAT],[8,0,HAT],[9,0,HAT],[10,0,HAT],
                    [4,1,HAT],[5,1,HAT],[6,1,HAT],[7,1,HAT],[8,1,HAT],[9,1,HAT],[10,1,HAT],[11,1,HAT],
                    [3,2,HAT],[4,2,HAT],[5,2,HAT],[6,2,HAT],[7,2,HAT],[8,2,HAT],[9,2,HAT],[10,2,HAT],[11,2,HAT],[12,2,HAT],
                    // Face
                    [6,3,SKIN],[7,3,SKIN],[8,3,SKIN],[9,3,SKIN],
                    [6,4,BLACK],[7,4,SKIN],[8,4,SKIN],[9,4,BLACK],
                    [7,5,SKIN],[8,5,SKIN_DARK],
                    // Trenchcoat
                    [5,6,BLUE],[6,6,BLUE],[7,6,BLUE],[8,6,BLUE],[9,6,BLUE],[10,6,BLUE],
                    [5,7,BLUE],[6,7,BLUE_D],[7,7,BLUE_D],[8,7,BLUE_D],[9,7,BLUE_D],[10,7,BLUE],
                    [4,8,BLUE],[5,8,BLUE],[6,8,BLUE],[7,8,BLUE],[8,8,BLUE],[9,8,BLUE],[10,8,BLUE],[11,8,BLUE],
                    [4,9,BLUE],[5,9,BLUE],[6,9,BLUE],[7,9,BLUE],[8,9,BLUE],[9,9,BLUE],[10,9,BLUE],[11,9,BLUE],
                    [4,10,BLUE_D],[5,10,BLUE_D],[6,10,BLUE_D],[7,10,BLUE_D],[8,10,BLUE_D],[9,10,BLUE_D],[10,10,BLUE_D],[11,10,BLUE_D],
                    // Collar
                    [5,6,'#3670A0'],[10,6,'#3670A0'],
                    // Magnifying glass (right hand)
                    [12,6,'#8B6914'],[12,7,'#8B6914'],[13,8,'#8B6914'],
                    [13,5,GRAY],[14,4,GRAY],[14,5,GRAY],[13,4,GRAY],[14,3,GRAY],[13,3,GRAY],
                    [13,6,GRAY],[14,6,GRAY],[14,5,'#ADD8E6'],
                    // Legs
                    [6,11,HAT],[7,11,HAT],[8,11,HAT],[9,11,HAT],
                    [6,12,HAT],[7,12,HAT],[8,12,HAT],[9,12,HAT],
                    // Shoes
                    [5,13,'#1A1A1A'],[6,13,'#1A1A1A'],[9,13,'#1A1A1A'],[10,13,'#1A1A1A'],
                    [5,14,'#1A1A1A'],[6,14,'#1A1A1A'],[9,14,'#1A1A1A'],[10,14,'#1A1A1A'],
                ];
            },
            accent: '#4A90C4',
        },

        // Scribe with quill
        'Reporting Agent': {
            body: () => {
                const GR = '#7C7C7C';
                const GR_D = '#5C5C5C';
                const PARCH = '#F5E6C8';
                return [
                    // Beret
                    [7,0,GR],[8,0,GR],
                    [6,1,GR],[7,1,GR_D],[8,1,GR_D],[9,1,GR],
                    // Face
                    [6,2,SKIN],[7,2,SKIN],[8,2,SKIN],[9,2,SKIN],
                    [6,3,BLACK],[7,3,SKIN],[8,3,SKIN],[9,3,BLACK],
                    [6,4,SKIN],[7,4,SKIN],[8,4,SKIN_DARK],[9,4,SKIN],
                    // Glasses
                    [5,3,'#444'],[10,3,'#444'],
                    // Robe
                    [6,5,GR],[7,5,GR],[8,5,GR],[9,5,GR],
                    [5,6,GR],[6,6,GR_D],[7,6,GR_D],[8,6,GR_D],[9,6,GR_D],[10,6,GR],
                    [5,7,GR],[6,7,GR],[7,7,GR],[8,7,GR],[9,7,GR],[10,7,GR],
                    [5,8,GR],[6,8,GR],[7,8,GR],[8,8,GR],[9,8,GR],[10,8,GR],
                    [5,9,GR_D],[6,9,GR_D],[7,9,GR_D],[8,9,GR_D],[9,9,GR_D],[10,9,GR_D],
                    // Arms
                    [4,6,SKIN],[4,7,SKIN],[11,6,SKIN],[11,7,SKIN],
                    // Quill (right hand)
                    [12,5,'#8B6914'],[12,4,'#8B6914'],[12,3,'#FFFFFF'],[12,2,'#FFFFFF'],[13,2,'#FFFFFF'],
                    // Scroll (left hand)
                    [1,6,PARCH],[2,6,PARCH],[3,6,PARCH],
                    [1,7,PARCH],[2,7,'#333'],[3,7,PARCH],
                    [1,8,PARCH],[2,8,'#333'],[3,8,PARCH],
                    [1,9,PARCH],[2,9,PARCH],[3,9,PARCH],
                    // Legs
                    [6,10,GR_D],[7,10,GR_D],[8,10,GR_D],[9,10,GR_D],
                    [6,11,GR_D],[7,11,GR_D],[8,11,GR_D],[9,11,GR_D],
                    // Shoes
                    [5,12,'#333'],[6,12,'#333'],[9,12,'#333'],[10,12,'#333'],
                    [5,13,'#333'],[6,13,'#333'],[9,13,'#333'],[10,13,'#333'],
                ];
            },
            accent: '#7C7C7C',
        },

        // Forensic investigator with flashlight
        'Forensics Agent': {
            body: () => {
                const DARK = '#2C3E50';
                const DARK_D = '#1A252F';
                const BEAM = '#FFFACD';
                const BEAM_D = '#FFE44D';
                return [
                    // Cap
                    [6,0,DARK],[7,0,DARK],[8,0,DARK],[9,0,DARK],
                    [5,1,DARK],[6,1,DARK_D],[7,1,DARK_D],[8,1,DARK_D],[9,1,DARK_D],[10,1,DARK],
                    // Face
                    [6,2,SKIN],[7,2,SKIN],[8,2,SKIN],[9,2,SKIN],
                    [6,3,BLACK],[7,3,SKIN],[8,3,SKIN],[9,3,BLACK],
                    [7,4,SKIN],[8,4,SKIN_DARK],
                    // Body (dark coat)
                    [6,5,DARK],[7,5,DARK],[8,5,DARK],[9,5,DARK],
                    [5,6,DARK],[6,6,DARK_D],[7,6,DARK_D],[8,6,DARK_D],[9,6,DARK_D],[10,6,DARK],
                    [5,7,DARK],[6,7,DARK],[7,7,DARK],[8,7,DARK],[9,7,DARK],[10,7,DARK],
                    [5,8,DARK],[6,8,DARK],[7,8,DARK],[8,8,DARK],[9,8,DARK],[10,8,DARK],
                    [5,9,DARK_D],[6,9,DARK_D],[7,9,DARK_D],[8,9,DARK_D],[9,9,DARK_D],[10,9,DARK_D],
                    // Badge
                    [7,6,'#FFD700'],[8,6,'#FFD700'],
                    // Arms
                    [4,6,SKIN],[4,7,SKIN],[11,6,SKIN],[11,7,SKIN],
                    // Flashlight (right hand)
                    [12,6,GRAY],[12,7,GRAY],[13,7,BEAM_D],
                    [14,6,BEAM],[14,7,BEAM],[14,8,BEAM],[15,5,BEAM],[15,6,BEAM],[15,7,BEAM],[15,8,BEAM],[15,9,BEAM],
                    // Legs
                    [6,10,DARK_D],[7,10,DARK_D],[8,10,DARK_D],[9,10,DARK_D],
                    [6,11,DARK_D],[7,11,DARK_D],[8,11,DARK_D],[9,11,DARK_D],
                    // Boots
                    [5,12,'#1A1A1A'],[6,12,'#1A1A1A'],[9,12,'#1A1A1A'],[10,12,'#1A1A1A'],
                    [5,13,'#1A1A1A'],[6,13,'#1A1A1A'],[9,13,'#1A1A1A'],[10,13,'#1A1A1A'],
                ];
            },
            accent: '#2C3E50',
        },

        // Robot surfer
        'Browser Agent': {
            body: () => {
                const CHROME = '#4285F4';
                const CHROME_D = '#2A65D0';
                const METAL = '#C0C0C0';
                const METAL_D = '#909090';
                return [
                    // Antenna
                    [7,0,'#FF0000'],[8,0,'#FF0000'],
                    [7,1,METAL_D],[8,1,METAL_D],
                    // Head (chrome helmet)
                    [5,2,CHROME],[6,2,CHROME],[7,2,CHROME],[8,2,CHROME],[9,2,CHROME],[10,2,CHROME],
                    [5,3,CHROME],[6,3,WHITE],[7,3,BLACK],[8,3,BLACK],[9,3,WHITE],[10,3,CHROME],
                    [5,4,CHROME_D],[6,4,CHROME_D],[7,4,CHROME_D],[8,4,CHROME_D],[9,4,CHROME_D],[10,4,CHROME_D],
                    // Body
                    [6,5,METAL],[7,5,METAL],[8,5,METAL],[9,5,METAL],
                    [5,6,METAL],[6,6,CHROME],[7,6,CHROME],[8,6,CHROME],[9,6,CHROME],[10,6,METAL],
                    [5,7,METAL],[6,7,METAL_D],[7,7,METAL_D],[8,7,METAL_D],[9,7,METAL_D],[10,7,METAL],
                    [5,8,METAL],[6,8,METAL],[7,8,METAL],[8,8,METAL],[9,8,METAL],[10,8,METAL],
                    // Screen on chest
                    [7,6,'#00FF00'],[8,6,'#00FF00'],
                    // Arms (metal)
                    [3,6,METAL_D],[4,6,METAL_D],[4,7,METAL_D],[11,6,METAL_D],[12,6,METAL_D],[11,7,METAL_D],
                    // Legs
                    [6,9,METAL_D],[7,9,METAL_D],[8,9,METAL_D],[9,9,METAL_D],
                    [6,10,METAL_D],[7,10,METAL_D],[8,10,METAL_D],[9,10,METAL_D],
                    // Surfboard
                    [2,11,'#FFD700'],[3,11,'#FFD700'],[4,11,'#FFD700'],[5,11,'#FFD700'],[6,11,'#FFD700'],
                    [7,11,'#FFD700'],[8,11,'#FFD700'],[9,11,'#FFD700'],[10,11,'#FFD700'],[11,11,'#FFD700'],
                    [12,11,'#CC9900'],[13,11,'#CC9900'],[1,11,'#CC9900'],
                    [13,12,'#CC9900'],[14,12,'#CC9900'],
                    // Feet on board
                    [5,12,METAL_D],[6,12,METAL_D],[9,12,METAL_D],[10,12,METAL_D],
                ];
            },
            accent: '#4285F4',
        },
    };

    // Alias
    CHARACTERS['Binary RE Agent'] = CHARACTERS['BinaryRE Agent'];

    // ── State overlays ─────────────────────────────────────────────
    // Additional SVG elements overlaid on the base character per state

    function thinkingOverlay() {
        return `<div class="avatar-overlay avatar-thinking">
            <svg viewBox="0 0 20 16" class="avatar-thought-bubbles">
                <circle cx="15" cy="4" r="3.5" fill="white" stroke="#ccc" stroke-width="0.5" class="thought-big"/>
                <circle cx="11" cy="10" r="2" fill="white" stroke="#ccc" stroke-width="0.5" class="thought-med"/>
                <circle cx="9" cy="13" r="1" fill="white" stroke="#ccc" stroke-width="0.5" class="thought-sm"/>
                <text x="15" y="5.5" text-anchor="middle" font-size="4" fill="#666">?</text>
            </svg>
        </div>`;
    }

    function writingOverlay() {
        return `<div class="avatar-overlay avatar-writing">
            <svg viewBox="0 0 16 16" class="avatar-pencil">
                <line x1="12" y1="2" x2="6" y2="14" stroke="#8B6914" stroke-width="1.5" stroke-linecap="round" class="pencil-line"/>
                <polygon points="6,14 5,16 8,15" fill="#FFD700" class="pencil-tip"/>
                <line x1="5" y1="15" x2="3" y2="15" stroke="#333" stroke-width="0.5" class="write-mark write-mark-1"/>
                <line x1="4" y1="14" x2="2" y2="14" stroke="#333" stroke-width="0.5" class="write-mark write-mark-2"/>
                <line x1="3" y1="13" x2="1" y2="13" stroke="#333" stroke-width="0.5" class="write-mark write-mark-3"/>
            </svg>
        </div>`;
    }

    function waitingOverlay() {
        return `<div class="avatar-overlay avatar-waiting">
            <svg viewBox="0 0 16 16" class="avatar-clock">
                <circle cx="12" cy="5" r="4" fill="white" stroke="#888" stroke-width="0.8"/>
                <line x1="12" y1="5" x2="12" y2="2.5" stroke="#333" stroke-width="0.8" stroke-linecap="round" class="clock-hand-min"/>
                <line x1="12" y1="5" x2="14" y2="5" stroke="#333" stroke-width="0.6" stroke-linecap="round" class="clock-hand-hr"/>
                <circle cx="12" cy="5" r="0.5" fill="#333"/>
            </svg>
            <div class="avatar-foot-tap"></div>
        </div>`;
    }

    function sleepingOverlay() {
        return `<div class="avatar-overlay avatar-sleeping">
            <svg viewBox="0 0 20 12" class="avatar-zzz">
                <text x="14" y="4" font-size="5" font-weight="bold" fill="#888" class="zzz zzz-1">Z</text>
                <text x="16" y="8" font-size="4" font-weight="bold" fill="#aaa" class="zzz zzz-2">z</text>
                <text x="18" y="11" font-size="3" font-weight="bold" fill="#ccc" class="zzz zzz-3">z</text>
            </svg>
        </div>`;
    }

    const STATE_OVERLAYS = {
        thinking: thinkingOverlay,
        writing: writingOverlay,
        waiting: waitingOverlay,
        sleeping: sleepingOverlay,
    };

    // ── Agent state tracking ───────────────────────────────────────
    const agentStates = {};

    function setState(agentName, state) {
        if (!['thinking', 'writing', 'waiting', 'sleeping'].includes(state)) return;
        const canonicalName = canonicalAgentName(agentName);
        agentStates[canonicalName] = state;
        updateAvatarDOM(canonicalName);
    }

    function getState(agentName) {
        return agentStates[canonicalAgentName(agentName)] || 'sleeping';
    }

    // ── Rendering ──────────────────────────────────────────────────

    function renderAvatar(agentName) {
        const canonicalName = canonicalAgentName(agentName);
        const char = CHARACTERS[canonicalName];
        if (!char) return '';

        const state = getState(canonicalName);
        const pixels = char.body();
        const spriteHtml = pixelGrid(pixels, 3);
        const overlayHtml = STATE_OVERLAYS[state] ? STATE_OVERLAYS[state]() : '';
        const stateLabel = state.charAt(0).toUpperCase() + state.slice(1);

        return `<div class="agent-avatar" data-agent="${canonicalName}" data-state="${state}">
            <div class="avatar-character ${state === 'sleeping' ? 'avatar-dim' : ''}">
                ${spriteHtml}
            </div>
            ${overlayHtml}
            <div class="avatar-state-label" style="color: ${char.accent}">${stateLabel}</div>
        </div>`;
    }

    function updateAvatarDOM(agentName) {
        const canonicalName = canonicalAgentName(agentName);
        const els = document.querySelectorAll(`.agent-avatar[data-agent="${canonicalName}"]`);
        els.forEach(el => {
            const parent = el.parentNode;
            if (!parent) return;
            const temp = document.createElement('div');
            temp.innerHTML = renderAvatar(canonicalName);
            const newEl = temp.firstElementChild;
            parent.replaceChild(newEl, el);
        });
    }

    // Initialize all agents as sleeping
    function initStates(agentNames) {
        for (const name of agentNames) {
            const canonicalName = canonicalAgentName(name);
            if (!agentStates[canonicalName]) agentStates[canonicalName] = 'sleeping';
        }
    }

    // ── SSE Event Handlers ─────────────────────────────────────────
    // Called from app.js SSE listeners

    function onAgentStart(agentName) {
        setState(agentName, 'thinking');
    }

    function onAgentComplete(agentName) {
        setState(agentName, 'sleeping');
    }

    function onToolStart(agentName) {
        setState(agentName, 'waiting');
    }

    function onToolComplete(agentName) {
        setState(agentName, 'thinking');
    }

    function onLLMToken(agentName) {
        // If we receive tokens, the agent is "writing" (generating output)
        const current = getState(agentName);
        if (current !== 'writing') {
            setState(agentName, 'writing');
        }
    }

    function onAgentTurn(agentName) {
        // New turn = thinking about next step
        setState(agentName, 'thinking');
    }

    return {
        renderAvatar,
        setState,
        getState,
        initStates,
        onAgentStart,
        onAgentComplete,
        onToolStart,
        onToolComplete,
        onLLMToken,
        onAgentTurn,
        CHARACTERS,
    };
})();
