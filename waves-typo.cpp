#include <windows.h>
#include <iostream>
#include <sstream>

#include <b58.c>

#include <botan\blake2b.h>
#include <botan\keccak.h>
#include <botan\sha2_32.h>
#pragma warning( push )
#pragma warning( disable : 4250 ) // inherits via dominance
#include <botan\curve25519.h>
#pragma warning( pop )

__declspec( align( 128 ) ) static uint8_t g_pubsechash[128];

struct waves_crypto
{
    waves_crypto() : _blake2b( 256 ), _keccak256( 256 ), _buf() {};

    auto sechash( uint8_t * data, size_t len )
    {
        _blake2b.update( data, len );
        _blake2b.final( _buf );
        _keccak256.update( _buf, 32 );
        _keccak256.final( _buf );
        return _buf;
    }

    auto pub( uint8_t * data, size_t len )
    {
        static const uint8_t _base9[32] = { 9 };

        _sha256.update( sechash( data, len ), 32 );
        _sha256.final( _buf );
        Botan::curve25519_donna( _buf, _buf, _base9 );
        return _buf;
    }

    auto pubsechash( uint8_t * data, size_t len )
    {
        return sechash( pub( data, len ), 32 );
    }

    Botan::Blake2b _blake2b;
    Botan::Keccak_1600 _keccak256;
    Botan::SHA_256 _sha256;
    uint8_t _buf[32];
};

static waves_crypto g_waves_crypto;
const char g_english[] = "abcdefghijklmnopqrstuvwxyz ";
char * g_seed;
size_t g_seed_len;

std::vector<std::string> seed_split( std::string str )
{
    std::istringstream split( str );
    std::vector<std::string> words;
    for( std::string word; std::getline( split, word, ' ' ); words.push_back( word ) );
    return words;
}

void seed_probe( uint8_t * seed, size_t len )
{
    if( 0 == memcmp( g_waves_crypto.pubsechash( seed, len ), g_pubsechash, 20 ) )
    {
        seed[len] = 0;
        std::cout << std::endl << "FOUND SEED = \"" << &seed[4] << "\"" << std::endl;
        ExitProcess( 0 );
    }
}

void set_pubsechash( char * address )
{
    uint8_t * buf = g_pubsechash;
    size_t len = sizeof( g_pubsechash );
    d58( address, strlen( address ), &buf, &len );

    if( buf[0] != 1 ||
        buf[1] != 'W' ||
        memcmp( &buf[22], g_waves_crypto.sechash( buf, 22 ), 4 ) )
    {
        std::cout << "Bad MAINNET address: " << address << std::endl;
        ExitProcess( 1 );
    }

    memmove( g_pubsechash, &buf[2], 20 );
}

int main( int argc, char ** argv )
{
    std::cout << "waves-typo (" << __DATE__ << ")" << std::endl;
    if( argc < 3 )
    {
        std::cout << "Usage: waves-typo.exe \"address\" \"seed\"" << std::endl;
        Sleep( 5000 );
        return 1;
    }

    set_pubsechash( argv[1] );
    g_seed = argv[2];
    g_seed_len = strlen( g_seed );

    uint8_t * seed = new uint8_t[g_seed_len + 4 + 2 + 32]();
    memcpy( &seed[4], g_seed, g_seed_len );
    seed_probe( seed, 4 + g_seed_len );

#if 1

#define DICTFULL { "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique", "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor", "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction", "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base", "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become", "beef", "before", "begin", "behave", "behind", "believe", "below", "belt", "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black", "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body", "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket", "brain", "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus", "business", "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable", "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can", "canal", "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable", "capital", "captain", "car", "carbon", "card", "cargo", "carpet", "carry", "cart", "case", "cash", "casino", "castle", "casual", "cat", "catalog", "catch", "category", "cattle", "caught", "cause", "caution", "cave", "ceiling", "celery", "cement", "census", "century", "cereal", "certain", "chair", "chalk", "champion", "change", "chaos", "chapter", "charge", "chase", "chat", "cheap", "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child", "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon", "circle", "citizen", "city", "civil", "claim", "clap", "clarify", "claw", "clay", "clean", "clerk", "clever", "click", "client", "cliff", "climb", "clinic", "clip", "clock", "clog", "close", "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch", "coach", "coast", "coconut", "code", "coffee", "coil", "coin", "collect", "color", "column", "combine", "come", "comfort", "comic", "common", "company", "concert", "conduct", "confirm", "congress", "connect", "consider", "control", "convince", "cook", "cool", "copper", "copy", "coral", "core", "corn", "correct", "cost", "cotton", "couch", "country", "couple", "course", "cousin", "cover", "coyote", "crack", "cradle", "craft", "cram", "crane", "crash", "crater", "crawl", "crazy", "cream", "credit", "creek", "crew", "cricket", "crime", "crisp", "critic", "crop", "cross", "crouch", "crowd", "crucial", "cruel", "cruise", "crumble", "crunch", "crush", "cry", "crystal", "cube", "culture", "cup", "cupboard", "curious", "current", "curtain", "curve", "cushion", "custom", "cute", "cycle", "dad", "damage", "damp", "dance", "danger", "daring", "dash", "daughter", "dawn", "day", "deal", "debate", "debris", "decade", "december", "decide", "decline", "decorate", "decrease", "deer", "defense", "define", "defy", "degree", "delay", "deliver", "demand", "demise", "denial", "dentist", "deny", "depart", "depend", "deposit", "depth", "deputy", "derive", "describe", "desert", "design", "desk", "despair", "destroy", "detail", "detect", "develop", "device", "devote", "diagram", "dial", "diamond", "diary", "dice", "diesel", "diet", "differ", "digital", "dignity", "dilemma", "dinner", "dinosaur", "direct", "dirt", "disagree", "discover", "disease", "dish", "dismiss", "disorder", "display", "distance", "divert", "divide", "divorce", "dizzy", "doctor", "document", "dog", "doll", "dolphin", "domain", "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft", "dragon", "drama", "drastic", "draw", "dream", "dress", "drift", "drill", "drink", "drip", "drive", "drop", "drum", "dry", "duck", "dumb", "dune", "during", "dust", "dutch", "duty", "dwarf", "dynamic", "eager", "eagle", "early", "earn", "earth", "easily", "east", "easy", "echo", "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight", "either", "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator", "elite", "else", "embark", "embody", "embrace", "emerge", "emotion", "employ", "empower", "empty", "enable", "enact", "end", "endless", "endorse", "enemy", "energy", "enforce", "engage", "engine", "enhance", "enjoy", "enlist", "enough", "enrich", "enroll", "ensure", "enter", "entire", "entry", "envelope", "episode", "equal", "equip", "era", "erase", "erode", "erosion", "error", "erupt", "escape", "essay", "essence", "estate", "eternal", "ethics", "evidence", "evil", "evoke", "evolve", "exact", "example", "excess", "exchange", "excite", "exclude", "excuse", "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit", "exotic", "expand", "expect", "expire", "explain", "expose", "express", "extend", "extra", "eye", "eyebrow", "fabric", "face", "faculty", "fade", "faint", "faith", "fall", "false", "fame", "family", "famous", "fan", "fancy", "fantasy", "farm", "fashion", "fat", "fatal", "father", "fatigue", "fault", "favorite", "feature", "february", "federal", "fee", "feed", "feel", "female", "fence", "festival", "fetch", "fever", "few", "fiber", "fiction", "field", "figure", "file", "film", "filter", "final", "find", "fine", "finger", "finish", "fire", "firm", "first", "fiscal", "fish", "fit", "fitness", "fix", "flag", "flame", "flash", "flat", "flavor", "flee", "flight", "flip", "float", "flock", "floor", "flower", "fluid", "flush", "fly", "foam", "focus", "fog", "foil", "fold", "follow", "food", "foot", "force", "forest", "forget", "fork", "fortune", "forum", "forward", "fossil", "foster", "found", "fox", "fragile", "frame", "frequent", "fresh", "friend", "fringe", "frog", "front", "frost", "frown", "frozen", "fruit", "fuel", "fun", "funny", "furnace", "fury", "future", "gadget", "gain", "galaxy", "gallery", "game", "gap", "garage", "garbage", "garden", "garlic", "garment", "gas", "gasp", "gate", "gather", "gauge", "gaze", "general", "genius", "genre", "gentle", "genuine", "gesture", "ghost", "giant", "gift", "giggle", "ginger", "giraffe", "girl", "give", "glad", "glance", "glare", "glass", "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue", "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip", "govern", "gown", "grab", "grace", "grain", "grant", "grape", "grass", "gravity", "great", "green", "grid", "grief", "grit", "grocery", "group", "grow", "grunt", "guard", "guess", "guide", "guilt", "guitar", "gun", "gym", "habit", "hair", "half", "hammer", "hamster", "hand", "happy", "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard", "head", "health", "heart", "heavy", "hedgehog", "height", "hello", "helmet", "help", "hen", "hero", "hidden", "high", "hill", "hint", "hip", "hire", "history", "hobby", "hockey", "hold", "hole", "holiday", "hollow", "home", "honey", "hood", "hope", "horn", "horror", "horse", "hospital", "host", "hotel", "hour", "hover", "hub", "huge", "human", "humble", "humor", "hundred", "hungry", "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid", "ice", "icon", "idea", "identify", "idle", "ignore", "ill", "illegal", "illness", "image", "imitate", "immense", "immune", "impact", "impose", "improve", "impulse", "inch", "include", "income", "increase", "index", "indicate", "indoor", "industry", "infant", "inflict", "inform", "inhale", "inherit", "initial", "inject", "injury", "inmate", "inner", "innocent", "input", "inquiry", "insane", "insect", "inside", "inspire", "install", "intact", "interest", "into", "invest", "invite", "involve", "iron", "island", "isolate", "issue", "item", "ivory", "jacket", "jaguar", "jar", "jazz", "jealous", "jeans", "jelly", "jewel", "job", "join", "joke", "journey", "joy", "judge", "juice", "jump", "jungle", "junior", "junk", "just", "kangaroo", "keen", "keep", "ketchup", "key", "kick", "kid", "kidney", "kind", "kingdom", "kiss", "kit", "kitchen", "kite", "kitten", "kiwi", "knee", "knife", "knock", "know", "lab", "label", "labor", "ladder", "lady", "lake", "lamp", "language", "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law", "lawn", "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave", "lecture", "left", "leg", "legal", "legend", "leisure", "lemon", "lend", "length", "lens", "leopard", "lesson", "letter", "level", "liar", "liberty", "library", "license", "life", "lift", "light", "like", "limb", "limit", "link", "lion", "liquid", "list", "little", "live", "lizard", "load", "loan", "lobster", "local", "lock", "logic", "lonely", "long", "loop", "lottery", "loud", "lounge", "love", "loyal", "lucky", "luggage", "lumber", "lunar", "lunch", "luxury", "lyrics", "machine", "mad", "magic", "magnet", "maid", "mail", "main", "major", "make", "mammal", "man", "manage", "mandate", "mango", "mansion", "manual", "maple", "marble", "march", "margin", "marine", "market", "marriage", "mask", "mass", "master", "match", "material", "math", "matrix", "matter", "maximum", "maze", "meadow", "mean", "measure", "meat", "mechanic", "medal", "media", "melody", "melt", "member", "memory", "mention", "menu", "mercy", "merge", "merit", "merry", "mesh", "message", "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind", "minimum", "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake", "mix", "mixed", "mixture", "mobile", "model", "modify", "mom", "moment", "monitor", "monkey", "monster", "month", "moon", "moral", "more", "morning", "mosquito", "mother", "motion", "motor", "mountain", "mouse", "move", "movie", "much", "muffin", "mule", "multiply", "muscle", "museum", "mushroom", "music", "must", "mutual", "myself", "mystery", "myth", "naive", "name", "napkin", "narrow", "nasty", "nation", "nature", "near", "neck", "need", "negative", "neglect", "neither", "nephew", "nerve", "nest", "net", "network", "neutral", "never", "news", "next", "nice", "night", "noble", "noise", "nominee", "noodle", "normal", "north", "nose", "notable", "note", "nothing", "notice", "novel", "now", "nuclear", "number", "nurse", "nut", "oak", "obey", "object", "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean", "october", "odor", "off", "offer", "office", "often", "oil", "okay", "old", "olive", "olympic", "omit", "once", "one", "onion", "online", "only", "open", "opera", "opinion", "oppose", "option", "orange", "orbit", "orchard", "order", "ordinary", "organ", "orient", "original", "orphan", "ostrich", "other", "outdoor", "outer", "output", "outside", "oval", "oven", "over", "own", "owner", "oxygen", "oyster", "ozone", "pact", "paddle", "page", "pair", "palace", "palm", "panda", "panel", "panic", "panther", "paper", "parade", "parent", "park", "parrot", "party", "pass", "patch", "path", "patient", "patrol", "pattern", "pause", "pave", "payment", "peace", "peanut", "pear", "peasant", "pelican", "pen", "penalty", "pencil", "people", "pepper", "perfect", "permit", "person", "pet", "phone", "photo", "phrase", "physical", "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot", "pink", "pioneer", "pipe", "pistol", "pitch", "pizza", "place", "planet", "plastic", "plate", "play", "please", "pledge", "pluck", "plug", "plunge", "poem", "poet", "point", "polar", "pole", "police", "pond", "pony", "pool", "popular", "portion", "position", "possible", "post", "potato", "pottery", "poverty", "powder", "power", "practice", "praise", "predict", "prefer", "prepare", "present", "pretty", "prevent", "price", "pride", "primary", "print", "priority", "prison", "private", "prize", "problem", "process", "produce", "profit", "program", "project", "promote", "proof", "property", "prosper", "protect", "proud", "provide", "public", "pudding", "pull", "pulp", "pulse", "pumpkin", "punch", "pupil", "puppy", "purchase", "purity", "purpose", "purse", "push", "put", "puzzle", "pyramid", "quality", "quantum", "quarter", "question", "quick", "quit", "quiz", "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio", "rail", "rain", "raise", "rally", "ramp", "ranch", "random", "range", "rapid", "rare", "rate", "rather", "raven", "raw", "razor", "ready", "real", "reason", "rebel", "rebuild", "recall", "receive", "recipe", "record", "recycle", "reduce", "reflect", "reform", "refuse", "region", "regret", "regular", "reject", "relax", "release", "relief", "rely", "remain", "remember", "remind", "remove", "render", "renew", "rent", "reopen", "repair", "repeat", "replace", "report", "require", "rescue", "resemble", "resist", "resource", "response", "result", "retire", "retreat", "return", "reunion", "reveal", "review", "reward", "rhythm", "rib", "ribbon", "rice", "rich", "ride", "ridge", "rifle", "right", "rigid", "ring", "riot", "ripple", "risk", "ritual", "rival", "river", "road", "roast", "robot", "robust", "rocket", "romance", "roof", "rookie", "room", "rose", "rotate", "rough", "round", "route", "royal", "rubber", "rude", "rug", "rule", "run", "runway", "rural", "sad", "saddle", "sadness", "safe", "sail", "salad", "salmon", "salon", "salt", "salute", "same", "sample", "sand", "satisfy", "satoshi", "sauce", "sausage", "save", "say", "scale", "scan", "scare", "scatter", "scene", "scheme", "school", "science", "scissors", "scorpion", "scout", "scrap", "screen", "script", "scrub", "sea", "search", "season", "seat", "second", "secret", "section", "security", "seed", "seek", "segment", "select", "sell", "seminar", "senior", "sense", "sentence", "series", "service", "session", "settle", "setup", "seven", "shadow", "shaft", "shallow", "share", "shed", "shell", "sheriff", "shield", "shift", "shine", "ship", "shiver", "shock", "shoe", "shoot", "shop", "short", "shoulder", "shove", "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side", "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar", "simple", "since", "sing", "siren", "sister", "situate", "six", "size", "skate", "sketch", "ski", "skill", "skin", "skirt", "skull", "slab", "slam", "sleep", "slender", "slice", "slide", "slight", "slim", "slogan", "slot", "slow", "slush", "small", "smart", "smile", "smoke", "smooth", "snack", "snake", "snap", "sniff", "snow", "soap", "soccer", "social", "sock", "soda", "soft", "solar", "soldier", "solid", "solution", "solve", "someone", "song", "soon", "sorry", "sort", "soul", "sound", "soup", "source", "south", "space", "spare", "spatial", "spawn", "speak", "special", "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin", "spirit", "split", "spoil", "sponsor", "spoon", "sport", "spot", "spray", "spread", "spring", "spy", "square", "squeeze", "squirrel", "stable", "stadium", "staff", "stage", "stairs", "stamp", "stand", "start", "state", "stay", "steak", "steel", "stem", "step", "stereo", "stick", "still", "sting", "stock", "stomach", "stone", "stool", "story", "stove", "strategy", "street", "strike", "strong", "struggle", "student", "stuff", "stumble", "style", "subject", "submit", "subway", "success", "such", "sudden", "suffer", "sugar", "suggest", "suit", "summer", "sun", "sunny", "sunset", "super", "supply", "supreme", "sure", "surface", "surge", "surprise", "surround", "survey", "suspect", "sustain", "swallow", "swamp", "swap", "swarm", "swear", "sweet", "swift", "swim", "swing", "switch", "sword", "symbol", "symptom", "syrup", "system", "table", "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target", "task", "taste", "tattoo", "taxi", "teach", "team", "tell", "ten", "tenant", "tennis", "tent", "term", "test", "text", "thank", "that", "theme", "then", "theory", "there", "they", "thing", "this", "thought", "three", "thrive", "throw", "thumb", "thunder", "ticket", "tide", "tiger", "tilt", "timber", "time", "tiny", "tip", "tired", "tissue", "title", "toast", "tobacco", "today", "toddler", "toe", "together", "toilet", "token", "tomato", "tomorrow", "tone", "tongue", "tonight", "tool", "tooth", "top", "topic", "topple", "torch", "tornado", "tortoise", "toss", "total", "tourist", "toward", "tower", "town", "toy", "track", "trade", "traffic", "tragic", "train", "transfer", "trap", "trash", "travel", "tray", "treat", "tree", "trend", "trial", "tribe", "trick", "trigger", "trim", "trip", "trophy", "trouble", "truck", "true", "truly", "trumpet", "trust", "truth", "try", "tube", "tuition", "tumble", "tuna", "tunnel", "turkey", "turn", "turtle", "twelve", "twenty", "twice", "twin", "twist", "two", "type", "typical", "ugly", "umbrella", "unable", "unaware", "uncle", "uncover", "under", "undo", "unfair", "unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown", "unlock", "until", "unusual", "unveil", "update", "upgrade", "uphold", "upon", "upper", "upset", "urban", "urge", "usage", "use", "used", "useful", "useless", "usual", "utility", "vacant", "vacuum", "vague", "valid", "valley", "valve", "van", "vanish", "vapor", "various", "vast", "vault", "vehicle", "velvet", "vendor", "venture", "venue", "verb", "verify", "version", "very", "vessel", "veteran", "viable", "vibrant", "vicious", "victory", "video", "view", "village", "vintage", "violin", "virtual", "virus", "visa", "visit", "visual", "vital", "vivid", "vocal", "voice", "void", "volcano", "volume", "vote", "voyage", "wage", "wagon", "wait", "walk", "wall", "walnut", "want", "warfare", "warm", "warrior", "wash", "wasp", "waste", "water", "wave", "way", "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding", "weekend", "weird", "welcome", "west", "wet", "whale", "what", "wheat", "wheel", "when", "where", "whip", "whisper", "wide", "width", "wife", "wild", "will", "win", "window", "wine", "wing", "wink", "winner", "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman", "wonder", "wood", "wool", "word", "work", "world", "worry", "worth", "wrap", "wreck", "wrestle", "wrist", "write", "wrong", "yard", "year", "yellow", "you", "young", "youth", "zebra", "zero", "zone", "zoo" }
    static const char * dict[] = DICTFULL;

    // 1 LAST WORD ADD
    std::cout << "1 LAST WORD ADD... ";
    seed[4 + g_seed_len] = ' ';
    for( size_t i = 0; i < 2048; i++ )
    {
        memcpy( &seed[4 + g_seed_len + 1], dict[i], strlen( dict[i] ) );
        seed_probe( seed, 4 + g_seed_len + 1 + strlen( dict[i] ) );
    }
    std::cout << "NO" << std::endl;
    memcpy( &seed[4], g_seed, g_seed_len );

    // 2 LAST WORDS ADD
    std::cout << "2 LAST WORDS ADD... ";
    seed[4 + g_seed_len] = ' ';
    for( size_t i = 0; i < 2048; i++ )
    {
        memcpy( &seed[4 + g_seed_len + 1], dict[i], strlen( dict[i] ) );
        seed[4 + g_seed_len + 1 + strlen( dict[i] )] = ' ';
        for( size_t j = 0; j < 2048; j++ )
        {
            if( i == j )
                continue;

            memcpy( &seed[4 + g_seed_len + 1 + strlen( dict[i] ) + 1], dict[j], strlen( dict[j] ) );
            seed_probe( seed, 4 + g_seed_len + 1 + strlen( dict[i] ) + 1 + strlen( dict[j] ) );
        }

        std::cout << 2048 - i << "... ";
    }
    std::cout << "NO" << std::endl;
    memcpy( &seed[4], g_seed, g_seed_len );

#else

    auto words = seed_split( g_seed );

    // 1 WORD MISS
    std::cout << "1 WORD MISS... ";
    for( size_t i = 0; i < words.size(); i++ )
    {
        size_t s = 0;
        for( size_t j = 0; j < words.size(); j++ )
        {
            if( i == j )
                continue;

            if( s )
                seed[4 + s++] = ' ';

            memcpy( &seed[4 + s], &words[j][0], words[j].size() );
            s += words[j].size();
        }

        seed_probe( seed, 4 + s );
    }
    std::cout << "NO" << std::endl;
    memcpy( &seed[4], g_seed, g_seed_len );

    // 2 WORDS MISS
    std::cout << "2 WORDS MISS... ";
    for( size_t i = 0; i < words.size(); i++ )
    for( size_t ii = i + 1; ii < words.size(); ii++ )
    {
        size_t s = 0;
        for( size_t j = 0; j < words.size(); j++ )
        {
            if( i == j || ii == j )
                continue;

            if( s )
                seed[4 + s++] = ' ';

            memcpy( &seed[4 + s], &words[j][0], words[j].size() );
            s += words[j].size();
        }

        seed_probe( seed, 4 + s );
    }
    std::cout << "NO" << std::endl;
    memcpy( &seed[4], g_seed, g_seed_len );

    // 1 LETTER MISS
    std::cout << "1 LETTER MISS... ";
    for( size_t i = 1; i < g_seed_len; i++ )
    {
        memcpy( &seed[4 + g_seed_len - i - 1], &g_seed[g_seed_len - i], i );

        seed_probe( seed, 4 + g_seed_len - 1 );

        memcpy( &seed[4], g_seed, g_seed_len );
    }
    std::cout << "NO" << std::endl;

    // 2 LETTERS MISS
    std::cout << "2 LETTERS MISS... ";
    for( size_t i = 0; i < g_seed_len - 1; i++ )
    {
        memcpy( &seed[4 + i], &g_seed[i + 1], g_seed_len - i - 1 );

        for( size_t j = i; j < g_seed_len - 1; j++ )
        {
            memcpy( &seed[4 + j], &g_seed[j + 2], g_seed_len - j - 1 );

            seed_probe( seed, 4 + g_seed_len - 2 );

            memcpy( &seed[4 + i], &g_seed[i + 1], g_seed_len - i - 1 );
        }

        memcpy( &seed[4], g_seed, g_seed_len );
    }
    std::cout << "NO" << std::endl;
    memcpy( &seed[4], g_seed, g_seed_len );

    // 1 WORD ADD
    std::cout << "1 WORD ADD... ";
    for( size_t i = 0; i < words.size() + 1; i++ )
    for( size_t k = 0; k < words.size(); k++ )
    {
        size_t s = 0;
        for( size_t j = 0; j < words.size(); j++ )
        {
            if( s )
                seed[4 + s++] = ' ';

            if( i == j )
            {
                memcpy( &seed[4 + s], &words[k][0], words[k].size() );
                s += words[k].size();
                seed[4 + s++] = ' ';
            }

            memcpy( &seed[4 + s], &words[j][0], words[j].size() );
            s += words[j].size();
        }

        if( i == words.size() )
        {
            seed[4 + s++] = ' ';
            memcpy( &seed[4 + s], &words[k][0], words[k].size() );
            s += words[k].size();
        }

        seed_probe( seed, 4 + s );
    }
    std::cout << "NO" << std::endl;
    memcpy( &seed[4], g_seed, g_seed_len );

    // 1 LETTER ADD
    std::cout << "1 LETTER ADD... ";
    for( size_t i = 0; i < g_seed_len - 1; i++ )
    {
        memcpy( &seed[4 + g_seed_len - i], &g_seed[g_seed_len - i - 1], i + 1 );
        for( size_t j = 0; j < sizeof( g_english ) - 1; j++ )
        {
            seed[4 + g_seed_len - i - 1] = g_english[j];

            seed_probe( seed, 4 + g_seed_len + 1 );
        }
    }
    std::cout << "NO" << std::endl;
    memcpy( &seed[4], g_seed, g_seed_len );

    // 1 LETTER TYPO
    std::cout << "1 LETTER TYPO... ";
    for( size_t i = 0; i < g_seed_len; i++ )
    {
        char c = seed[4 + i];
        for( size_t j = 0; j < sizeof( g_english ) - 1; j++ )
        {
            seed[4 + i] = g_english[j];

            seed_probe( seed, 4 + g_seed_len );
        }
        seed[4 + i] = c;
    }
    std::cout << "NO" << std::endl;

    // 1 LETTER MISS + 1 LETTER TYPO
    std::cout << "1 LETTER MISS + 1 LETTER TYPO... " << g_seed_len - 1 << "... ";
    for( size_t i = 1; i < g_seed_len; i++ )
    {
        memcpy( &seed[4 + g_seed_len - i - 1], &g_seed[g_seed_len - i], i );

        for( size_t k = 0; k < g_seed_len - 1; k++ )
        {
            char c2 = seed[4 + k];
            for( size_t m = 0; m < sizeof( g_english ) - 1; m++ )
            {
                seed[4 + k] = g_english[m];

                seed_probe( seed, 4 + g_seed_len - 1 );
            }
            seed[4 + k] = c2;
        }

        std::cout << g_seed_len - i - 1 << "... ";
    }
    std::cout << "NO" << std::endl;
    memcpy( &seed[4], g_seed, g_seed_len );

    // 2 LETTERS TYPO
    std::cout << "2 LETTERS TYPO... " << g_seed_len << "... ";
    for( size_t i = 0; i < g_seed_len; i++ )
    {
        char c1 = seed[4 + i];
        for( size_t j = 0; j < sizeof( g_english ) - 1; j++ )
        {
            seed[4 + i] = g_english[j];

            for( size_t k = i + 1; k < g_seed_len; k++ )
            {
                char c2 = seed[4 + k];
                for( size_t m = 0; m < sizeof( g_english ) - 1; m++ )
                {
                    seed[4 + k] = g_english[m];

                    seed_probe( seed, 4 + g_seed_len );
                }
                seed[4 + k] = c2;
            }
        }
        seed[4 + i] = c1;

        std::cout << g_seed_len - i - 1 << "... ";
    }
    std::cout << "NO" << std::endl;

    // 1 LETTER ADD + 1 LETTER TYPO
    std::cout << "1 LETTER ADD + 1 LETTER TYPO... " << g_seed_len - 1 << "... ";
    for( size_t i = 0; i < g_seed_len - 1; i++ )
    {
        memcpy( &seed[4 + g_seed_len - i], &g_seed[g_seed_len - i - 1], i + 1 );
        for( size_t j = 0; j < sizeof( g_english ) - 1; j++ )
        {
            seed[4 + g_seed_len - i - 1] = g_english[j];

            for( size_t k = 0; k < g_seed_len + 1; k++ )
            {
                char c2 = seed[4 + k];
                for( size_t m = 0; m < sizeof( g_english ) - 1; m++ )
                {
                    seed[4 + k] = g_english[m];

                    seed_probe( seed, 4 + g_seed_len + 1 );
                }
                seed[4 + k] = c2;
            }
        }

        std::cout << g_seed_len - i - 2 << "... ";
    }
    std::cout << "NO" << std::endl;
    memcpy( &seed[4], g_seed, g_seed_len );

#endif

    std::cout << "NOT FOUND" << std::endl;
    return 1;
}
