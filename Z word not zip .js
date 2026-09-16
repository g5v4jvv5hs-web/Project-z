const CORE_TRUTHS = Object.freeze([
  "You have never seen the present. Every image reaches you after the event.",
  "Each eye contains a blind spot. Your brain fills the missing region without telling you.",
  "Your nose is almost always in your field of view. Your brain usually filters it out.",
  "During rapid eye movements, visual sensitivity briefly drops. Your brain hides the interruption.",
  "Memory is reconstructed when recalled, not played back like a recording.",
  "Confidence in a memory does not guarantee that the memory is accurate.",
  "Attention can make a visible object disappear from awareness without changing the object.",
  "Color is a perception built by the brain from wavelengths of light.",
  "The same sensory input can produce different perceptions depending on context.",
  "Phantom-limb pain can occur in a body part that is no longer there.",
  "Your brain can treat tools as temporary extensions of the body.",
  "Neural activity related to movement can begin before a person reports conscious awareness of moving.",
  "Your brain predicts incoming sensory information and updates the prediction when signals arrive.",
  "Dreams can activate many brain regions used during waking perception.",
  "Brain tissue itself lacks pain receptors. Head pain comes from surrounding structures.",
  "Your pupils change with more than brightness. Attention and arousal can alter them.",
  "Your heartbeat changes slightly with breathing.",
  "Your nervous system uses electrical impulses and chemical signals at the same time.",
  "Your heart creates electrical signals that can be detected at the skin.",
  "Your brain creates measurable electrical rhythms.",
  "Your body emits infrared radiation continuously.",
  "Human vision detects only a narrow band of the electromagnetic spectrum.",
  "Human hearing detects only part of the pressure waves that exist around us.",
  "Some animals detect ultraviolet light that human eyes cannot see.",
  "Many animals can sense magnetic fields that humans do not consciously perceive.",
  "Cosmic-ray particles pass through your body and your surroundings.",
  "Enormous numbers of solar neutrinos pass through your body every second.",
  "Atomic nuclei occupy only a tiny fraction of an atom's volume.",
  "The resistance you feel when touching matter is largely electromagnetic.",
  "Empty space is not the same as absolute nothingness.",
  "Quantum fields have measurable effects even in vacuum.",
  "Light shows both wave-like and particle-like behavior.",
  "Matter particles can show wave-like behavior.",
  "Quantum entanglement produces correlations that have been experimentally verified.",
  "Entanglement does not allow ordinary faster-than-light messaging.",
  "Quantum outcomes are generally described by probabilities.",
  "Gravity changes the rate at which clocks tick.",
  "Motion changes the rate at which clocks tick.",
  "GPS requires relativistic time corrections to remain accurate.",
  "Gravity can bend light.",
  "Massive objects can magnify distant objects through gravitational lensing.",
  "Gravitational waves are ripples in spacetime and have been directly detected.",
  "Black-hole mergers can produce gravitational waves detectable across enormous distances.",
  "An event horizon marks a boundary beyond which light cannot escape to distant observers.",
  "Sunlight takes about eight minutes and twenty seconds to reach Earth.",
  "The sunlight you see left the Sun before you became aware of it.",
  "Looking farther into space means looking farther back in time.",
  "Some starlight reaching Earth began its journey before humans existed.",
  "The night sky is a record of different moments, not a single present.",
  "There is no known central point of the universe.",
  "The observable universe is not necessarily the entire universe.",
  "We do not know the total size of the universe.",
  "The expansion of the universe is accelerating.",
  "Space itself expands between sufficiently distant, unbound galaxies.",
  "Some regions of the universe are permanently beyond our future reach because of cosmic expansion.",
  "The cosmic microwave background is ancient light released when the universe became transparent.",
  "Tiny early density differences grew into galaxies and large-scale cosmic structure.",
  "Dark matter is inferred from its gravitational effects, but its particle identity remains unknown.",
  "Dark energy is a name for the cause of cosmic acceleration that we do not yet fully understand.",
  "The Sun converts mass into energy every second.",
  "The Sun loses mass as radiation and solar wind escape.",
  "Light carries momentum even though photons have no rest mass.",
  "Earth is rotating while you feel still.",
  "Earth is orbiting the Sun while the ground feels stationary.",
  "The Solar System is moving through the Milky Way.",
  "The Milky Way is moving relative to other galaxies.",
  "You have never occupied exactly the same position in space relative to every reference frame.",
  "There is no experimentally established absolute state of rest.",
  "The Moon is slowly moving away from Earth.",
  "Earth's rotation changes over geological time.",
  "Continents move a few centimeters per year.",
  "Earth's magnetic poles move over time.",
  "Earth's magnetic field has reversed many times in the geological past.",
  "Most of the deep ocean exists in permanent darkness.",
  "Pressure in the deepest ocean trenches exceeds a thousand times surface atmospheric pressure.",
  "Sound travels faster in water than in air.",
  "Low-frequency sound can travel enormous distances through the ocean.",
  "Your bones are living tissue and are continuously remodeled.",
  "Your skin continuously sheds microscopic cells.",
  "Your body constantly exchanges matter with the environment.",
  "Different human cells can have very different lifespans.",
  "Cells repair DNA damage constantly.",
  "Mutations occur naturally when cells copy DNA.",
  "Programmed cell death is a normal part of keeping a body alive.",
  "Your immune system can remember pathogens you no longer consciously remember.",
  "Trillions of microorganisms live on and inside the human body.",
  "Mitochondria descend from bacteria that once lived independently.",
  "Mitochondria carry their own DNA.",
  "Parts of the human genome are remnants of ancient retroviral infections.",
  "Some genes important to mammalian placentas have viral ancestry.",
  "All known life on Earth uses closely related genetic machinery.",
  "The genetic code is nearly universal across known life.",
  "Hydrogen in your body was formed in the early universe.",
  "Many heavier elements in your body were forged inside stars.",
  "Elements such as gold can be produced in extreme events including neutron-star mergers.",
  "The calcium in your bones existed before Earth formed.",
  "The iron in your blood came from astrophysical processes older than the Solar System.",
  "Evidence indicates that some water in the Solar System formed before the Sun.",
  "Your cells contain molecular clocks that respond to daily cycles.",
  "Sleep changes how memories are consolidated."
]);

const CHANNELS = Object.freeze([
  "OBS",
  "SIGNAL",
  "ARCHIVE",
  "TRACE",
  "NODE"
]);

export const MYSTERY_MESSAGES = Object.freeze(
  CHANNELS.flatMap(
    (channel, channelIndex) =>
      CORE_TRUTHS.map(
        (truth, truthIndex) => {
          const serial =
            channelIndex * CORE_TRUTHS.length +
            truthIndex +
            1;

          return (
            `Z/${channel}-${String(serial).padStart(3, "0")} // ` +
            truth
          );
        }
      )
  )
);

if (MYSTERY_MESSAGES.length !== 500) {
  throw new Error(
    `Expected 500 mystery messages, got ${MYSTERY_MESSAGES.length}`
  );
}
