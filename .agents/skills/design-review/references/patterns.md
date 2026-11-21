# GoF design patterns — reference

Read this only when the problem-first map in SKILL.md points you at a pattern and
you need to be precise about what it is. Each entry gives the **intent**, the
genuine **trigger** ("use when"), and the over-engineering **warning** ("skip
when"), so you recommend from evidence rather than memory. Patterns are grouped
Creational / Structural / Behavioural.

## Creational

### Abstract Factory
Provides an interface for creating families of related objects without naming their concrete classes.
- **Use when:** several objects must always be used together as a set (a UI theme, a DB driver + dialect) and you want the whole family swappable as one unit.
- **Skip when:** there's a single product, or the products aren't mutually dependent — a Factory Method or a plain function is enough.

### Builder
Separates the construction of a complex object from its representation, step by step.
- **Use when:** an object has many optional or configurable parts, or you're assembling an immutable object incrementally.
- **Skip when:** the object has two or three parameters — a plain constructor or function is clearer.

### Factory Method
Defines an interface for creating an object, but lets the subclass (or the caller) decide which class to instantiate.
- **Use when:** a class can't know in advance which concrete type it needs, and creation should be a single overridable step.
- **Skip when:** the variation is trivial — one `new`/function call at the call site is fine.

### Prototype
Creates new objects by cloning an existing instance rather than building from scratch.
- **Use when:** construction is expensive, or instances differ only in a few fields, or you want runtime-configured object graphs.
- **Skip when:** construction is cheap and clear. In Python use `copy.copy`/`copy.deepcopy`; in JS `structuredClone`/`Object.create`.

### Singleton
Ensures a class has one instance and provides a global point of access to it.
- **Use when:** a single shared resource genuinely must exist (connection pool, logger).
- **Skip when:** you mostly want convenience — global mutable state complicates tests. Prefer dependency injection, which gives "one instance" via the injector without the global.

## Structural

### Adapter
Converts one interface into another a client expects, so incompatible things can work together.
- **Use when:** you must use an existing class whose interface doesn't match, and you can't change either side.
- **Skip when:** you control both sides — align the interfaces directly. Often a thin wrapper function or class.

### Bridge
Decouples an abstraction from its implementation so the two can vary independently.
- **Use when:** a hierarchy is multiplying along two axes (N shapes × M renderers → N×M classes).
- **Skip when:** there's only one axis of variation — a Bridge over one dimension is overkill.

### Composite
Composes objects into trees so an individual and a group can be treated uniformly.
- **Use when:** part-whole hierarchies where a client shouldn't care whether it holds one or many (filesystems, UI trees, expressions).
- **Skip when:** the structure is flat and no uniform treatment is needed.

### Decorator
Attaches responsibilities to an object dynamically, without subclassing.
- **Use when:** behaviour is added or removed per-instance, or many behaviours stack (validation, caching, logging) without a subclass per combination.
- **Skip when:** the behaviour is fixed per-type — a subclass or a parameter is simpler.

### Facade
Provides a unified, simplified interface to a subsystem.
- **Use when:** callers must orchestrate several classes for one common task; hide that behind one call.
- **Skip when:** the "subsystem" is one or two classes — a facade over nothing is a middleman.

### Flyweight
Shares common state across many objects to save memory.
- **Use when:** a large number of objects with mostly-identical intrinsic state (glyphs, tiles).
- **Skip when:** object count or memory isn't an actual problem — premature.

### Proxy
Controls access to an object through a stand-in.
- **Use when:** you need lazy loading, remote access, access control, or logging without changing the target.
- **Skip when:** direct access is fine and you don't need the interception point.

## Behavioural

### Chain of Responsibility
Passes a request along a chain of handlers until one handles it.
- **Use when:** several handlers might process a request and the sender shouldn't know which, or the chain is runtime-configurable.
- **Skip when:** there's one fixed handler and a fixed order — a plain function is clearer.

### Command
Encapsulates a request as an object.
- **Use when:** you need to queue, log, schedule, or undo operations, or parameterize an invoker with a request.
- **Skip when:** you're calling a function once — a bare function or lambda is the Command in most dynamic languages.

### Interpreter
Represents a grammar and evaluates sentences in it.
- **Use when:** you're building a small DSL or expression evaluator with a real grammar.
- **Skip when:** the language is simple — a regex, parser combinator, or hand-rolled function beats the full machinery. Rarely the right call in application code.

### Iterator
Traverses a collection without exposing its representation.
- **Use when:** traversal is non-trivial or needs multiple simultaneous cursors.
- **Skip when:** the language ships iteration for free (Python `__iter__`/generators, JS iterables, Go channels) — most do.

### Mediator
Centralizes many-to-many communication so components don't talk to each other directly.
- **Use when:** several components are tangled in a web of references and you want to route through one hub.
- **Skip when:** the coupling is one-to-one or simple — a direct call or an Observer is fine.

### Memento
Captures and restores an object's internal state without exposing it.
- **Use when:** you need undo/redo or checkpoints.
- **Skip when:** the state is already copyable (immutable value objects) — just copy it; Memento is for encapsulating private state.

### Observer
A one-to-many dependency: when one object changes, its dependents are notified.
- **Use when:** state changes must propagate to multiple consumers the source shouldn't know about.
- **Skip when:** there's one consumer the source can call directly. Event emitters, callbacks, signals, and reactive streams are Observer idioms.

### State
Lets an object change behaviour when its internal state changes, as if it changed class.
- **Use when:** behaviour is driven by a small set of states and you'd otherwise scatter conditionals on state everywhere.
- **Skip when:** the state machine is tiny (two states, one branch) — an `if` is clearer.

### Strategy
Defines a family of interchangeable algorithms and selects one at runtime.
- **Use when:** one operation has multiple implementations chosen by context, and you want to add new ones without editing callers.
- **Skip when:** there's one algorithm, or the variation is a single branch. In Python/JS/Go a Strategy is usually just a first-class function or a small one-method object — no class hierarchy needed.

### Template Method
Defines the skeleton of an algorithm in a base method, deferring steps to subclasses.
- **Use when:** several algorithms share a fixed structure with a few varying steps.
- **Skip when:** the steps vary enough that composition is cleaner — when in doubt, prefer Strategy over inheritance-based Template Method.

### Visitor
Adds operations to an object structure without changing the classes.
- **Use when:** you have a stable set of element classes and many operations, and adding operations should not touch the elements.
- **Skip when:** the element set changes often — every new element forces an update to every visitor. Usually overkill outside compilers and parsers; prefer Strategy/polymorphism.
